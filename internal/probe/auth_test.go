package probe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pyck-ai/pyck-debug-worker/internal/secret"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// testToken stands in for an opaque personal access token.
const testToken = "pat_not_a_real_credential_000000"

// gatewayStub serves one canned GraphQL answer and records what it received.
type gatewayStub struct {
	status int
	body   string

	gotAuth   string
	gotQuery  string
	gotMethod string
}

func (g *gatewayStub) server(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.gotAuth = r.Header.Get("Authorization")
		g.gotMethod = r.Method

		var payload struct {
			Query string `json:"query"`
		}

		_ = json.NewDecoder(r.Body).Decode(&payload)
		g.gotQuery = payload.Query

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(g.status)
		_, _ = w.Write([]byte(g.body))
	}))
	t.Cleanup(server.Close)

	return server
}

func TestPATStages(t *testing.T) {
	const tenantID = "0198f4d2-0000-7000-8000-000000000001"

	tests := []struct {
		name string
		stub gatewayStub
		// opts carries the cross-check inputs.
		namespace string
		wantOK    []bool
		wantStage []string
		contains  []string
	}{
		{
			name: "success resolves the tenant in one request",
			stub: gatewayStub{
				status: http.StatusOK,
				body: `{"data":{"me":{"TenantID":"` + tenantID +
					`","TenantName":"acme","UserID":"u1","Username":"svc-worker"}}}`,
			},
			wantOK:    []bool{true, true},
			wantStage: []string{"auth", "tenant"},
			contains:  []string{"GetMe 200 user=svc-worker", tenantID + ` "acme" via=api`},
		},
		{
			name: "200 with a graphql error is still a failure",
			stub: gatewayStub{
				status: http.StatusOK,
				body: `{"data":null,"errors":[{"message":"token is expired",` +
					`"extensions":{"code":"UNAUTHENTICATED"}}]}`,
			},
			wantOK:    []bool{false},
			wantStage: []string{"auth"},
			contains:  []string{"GetMe 200 UNAUTHENTICATED: token is expired"},
		},
		{
			name: "non-200",
			stub: gatewayStub{status: http.StatusBadGateway, body: `{}`},
			// A 502 stops the ladder: there is no identity to report.
			wantOK:    []bool{false},
			wantStage: []string{"auth"},
			contains:  []string{"GetMe 502"},
		},
		{
			name: "mismatch against TEMPORAL_NAMESPACE is the loudest signal",
			stub: gatewayStub{
				status: http.StatusOK,
				body: `{"data":{"me":{"TenantID":"` + tenantID +
					`","TenantName":"acme","UserID":"u1","Username":"svc-worker"}}}`,
			},
			namespace: "0198f4d2-0000-7000-8000-999999999999",
			wantOK:    []bool{true, true, false},
			wantStage: []string{"auth", "tenant", "tenant"},
			contains: []string{
				"TEMPORAL_NAMESPACE=0198f4d2-0000-7000-8000-999999999999",
				"!= resolved " + tenantID,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := tc.stub
			server := stub.server(t)

			results := patStages(t.Context(), testTarget, Options{
				Token:             secret.New(testToken),
				GatewayURL:        server.URL,
				TemporalNamespace: tc.namespace,
			})

			if len(results) != len(tc.wantOK) {
				t.Fatalf("got %d results, want %d: %+v", len(results), len(tc.wantOK), results)
			}

			for i, want := range tc.wantOK {
				if results[i].OK != want {
					t.Errorf("result %d (%s) OK = %v, want %v (detail %q)",
						i, results[i].Stage, results[i].OK, want, results[i].Detail)
				}

				if results[i].Stage != tc.wantStage[i] {
					t.Errorf("result %d stage = %q, want %q", i, results[i].Stage, tc.wantStage[i])
				}
			}

			joined := ""
			for _, r := range results {
				joined += r.Detail + "\n"
			}

			for _, want := range tc.contains {
				if !strings.Contains(joined, want) {
					t.Errorf("details %q do not contain %q", joined, want)
				}
			}

			if stub.gotMethod != http.MethodPost {
				t.Errorf("method = %q, want POST", stub.gotMethod)
			}

			if stub.gotAuth != "Bearer "+testToken {
				t.Errorf("Authorization header = %q", stub.gotAuth)
			}

			if stub.gotQuery != getMeQuery {
				t.Errorf("query = %q, want %q", stub.gotQuery, getMeQuery)
			}
		})
	}
}

func TestPATStagesTransportErrorRedactsURL(t *testing.T) {
	server := (&gatewayStub{status: http.StatusOK, body: `{}`}).server(t)
	closed := server.URL

	server.Close()

	results := patStages(t.Context(), testTarget, Options{
		Token:      secret.New(testToken),
		GatewayURL: closed,
	})

	if len(results) != 1 || results[0].OK {
		t.Fatalf("want a single failing auth result, got %+v", results)
	}

	if strings.Contains(results[0].Detail, testToken) {
		t.Fatalf("the credential reached the detail: %q", results[0].Detail)
	}
}

func TestGatewayEndpoint(t *testing.T) {
	tgt := target.Target{Host: "test.pyck.cloud", Port: 443, Kind: target.KindHTTPS}

	tests := []struct {
		name string
		opts Options
		want string
	}{
		{
			name: "defaults to the app domain being probed",
			want: "https://test.pyck.cloud:443/graphql",
		},
		{
			name: "bare gateway url gets the graphql path",
			opts: Options{GatewayURL: "https://gateway.pyck.cloud"},
			want: "https://gateway.pyck.cloud/graphql",
		},
		{
			name: "trailing slash only",
			opts: Options{GatewayURL: "https://gateway.pyck.cloud/"},
			want: "https://gateway.pyck.cloud/graphql",
		},
		{
			name: "explicit path is left alone",
			opts: Options{GatewayURL: "https://gateway.pyck.cloud/api/graphql"},
			want: "https://gateway.pyck.cloud/api/graphql",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := gatewayEndpoint(tgt, tc.opts); got != tc.want {
				t.Errorf("gatewayEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthVerdict(t *testing.T) {
	tests := []struct {
		name   string
		in     getMeResult
		wantOK bool
		want   string
	}{
		{
			name:   "ok falls back to the user id when there is no username",
			in:     getMeResult{status: 200, body: mustResponse(t, `{"data":{"me":{"UserID":"u1"}}}`)},
			wantOK: true,
			want:   "GetMe 200 user=u1",
		},
		{
			name: "graphql error without an extensions code",
			in: getMeResult{
				status: 200,
				body:   mustResponse(t, `{"errors":[{"message":"boom"}]}`),
			},
			wantOK: false,
			want:   "GetMe 200 boom",
		},
		{
			name:   "401",
			in:     getMeResult{status: 401, body: getMeResponse{}},
			wantOK: false,
			want:   "GetMe 401",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, detail := authVerdict(tc.in)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}

			if detail != tc.want {
				t.Errorf("detail = %q, want %q", detail, tc.want)
			}
		})
	}
}

// mustResponse decodes a GraphQL envelope for the table above.
func mustResponse(t *testing.T, raw string) getMeResponse {
	t.Helper()

	var out getMeResponse
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	return out
}
