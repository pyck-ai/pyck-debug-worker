package probe

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// makeJWT builds an unsigned token with the given payload. The signature is
// never checked, so a constant stands in for it.
func makeJWT(t *testing.T, payload any) string {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	return header + "." + base64.RawURLEncoding.EncodeToString(body) + ".c2ln"
}

func TestDecodeJWT(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		wantOK bool
		want   jwtClaims
	}{
		{
			name: "pyck tenant claim",
			token: makeJWT(t, map[string]string{
				"pyck_tenant_id": "0198f4d2-0000-7000-8000-000000000001",
				"iss":            "https://auth.test.pyck.cloud",
			}),
			wantOK: true,
			want: jwtClaims{
				TenantID: "0198f4d2-0000-7000-8000-000000000001",
				Issuer:   "https://auth.test.pyck.cloud",
			},
		},
		{
			name: "zitadel resource owner claim",
			token: makeJWT(t, map[string]string{
				"iss":      "https://auth.test.pyck.cloud",
				orgIDClaim: "310000000000000001",
			}),
			wantOK: true,
			want: jwtClaims{
				Issuer: "https://auth.test.pyck.cloud",
				OrgID:  "310000000000000001",
			},
		},
		{name: "opaque pat is not a jwt", token: "pat_abcdefghijklmnop", wantOK: false},
		{name: "two segments", token: "aaa.bbb", wantOK: false},
		{
			name:   "three dotted segments that are not base64",
			token:  "not!base64.not!base64.sig",
			wantOK: false,
		},
		{
			name: "payload is not a json object",
			token: header() + "." +
				base64.RawURLEncoding.EncodeToString([]byte(`"just a string"`)) + ".sig",
			wantOK: false,
		},
		{
			name: "header is not json",
			token: base64.RawURLEncoding.EncodeToString([]byte("nope")) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`)) + ".sig",
			wantOK: false,
		},
		{name: "empty", token: "", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeJWT(tc.token)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}

			if ok && got != tc.want {
				t.Errorf("claims = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// header is a valid encoded JWT header.
func header() string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
}

// uuidV5 is an independent RFC 4122 v5 implementation, so the test does not
// verify the uuid package against itself.
func uuidV5(namespace [16]byte, name string) string {
	sum := sha1.Sum(append(namespace[:], name...)) //nolint:gosec // UUIDv5 is defined on SHA-1

	var out [16]byte

	copy(out[:], sum[:16])

	out[6] = (out[6] & 0x0f) | 0x50 // version 5
	out[8] = (out[8] & 0x3f) | 0x80 // RFC 4122 variant

	return fmt.Sprintf("%x-%x-%x-%x-%x", out[0:4], out[4:6], out[6:8], out[8:10], out[10:16])
}

func TestComputeTenantUUID(t *testing.T) {
	const (
		issuer = "https://auth.test.pyck.cloud"
		orgID  = "310000000000000001"
	)

	// The known vector: a UUIDv5 of the org id inside a namespace that is
	// itself a UUIDv5 of the issuer under the OID namespace.
	nameSpaceOID := [16]byte{
		0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1,
		0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
	}

	issuerNS := uuidV5(nameSpaceOID, issuer)

	var raw [16]byte

	hexOnly := strings.ReplaceAll(issuerNS, "-", "")
	for i := range raw {
		var b byte

		if _, err := fmt.Sscanf(hexOnly[i*2:i*2+2], "%02x", &b); err != nil {
			t.Fatalf("parse namespace: %v", err)
		}

		raw[i] = b
	}

	want := uuidV5(raw, orgID)

	if got := computeTenantUUID(issuer, orgID).String(); got != want {
		t.Errorf("computeTenantUUID() = %s, want %s", got, want)
	}

	// Pinned so a change in the derivation cannot pass by changing both sides.
	const pinned = "79007f57-8671-5529-93ab-ff095f6f47d6"

	if want != pinned {
		t.Errorf("independent vector = %s, want the pinned %s", want, pinned)
	}
}

func TestTenantFromClaims(t *testing.T) {
	tests := []struct {
		name    string
		claims  jwtClaims
		wantID  string
		wantVia string
	}{
		{
			name:    "explicit claim wins",
			claims:  jwtClaims{TenantID: "abc", Issuer: "https://auth.test.pyck.cloud", OrgID: "31"},
			wantID:  "abc",
			wantVia: viaJWTClaim,
		},
		{
			name:    "derived from issuer and org",
			claims:  jwtClaims{Issuer: "https://auth.test.pyck.cloud", OrgID: "310000000000000001"},
			wantID:  computeTenantUUID("https://auth.test.pyck.cloud", "310000000000000001").String(),
			wantVia: viaComputed,
		},
		{name: "nothing to work with", claims: jwtClaims{}, wantID: "", wantVia: viaComputed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tenantFromClaims(tc.claims)
			if got.id != tc.wantID {
				t.Errorf("id = %q, want %q", got.id, tc.wantID)
			}

			if got.via != tc.wantVia {
				t.Errorf("via = %q, want %q", got.via, tc.wantVia)
			}
		})
	}
}

func TestCrossCheck(t *testing.T) {
	resolved := tenant{id: "0198f4d2-0000-7000-8000-000000000001", name: "acme", via: viaAPI}

	tests := []struct {
		name      string
		namespace string
		tenantID  string
		wantRun   bool
		wantOK    bool
		contains  []string
	}{
		{
			name:    "neither set stays silent",
			wantRun: false,
		},
		{
			name:      "both agree",
			namespace: resolved.id,
			tenantID:  resolved.id,
			wantRun:   true,
			wantOK:    true,
			contains:  []string{"== TEMPORAL_NAMESPACE", "== PYCK_API_TENANT_ID"},
		},
		{
			name:      "only namespace set names only that one",
			namespace: resolved.id,
			wantRun:   true,
			wantOK:    true,
			contains:  []string{"== TEMPORAL_NAMESPACE"},
		},
		{
			name:      "namespace mismatch shows both values",
			namespace: "0198f4d2-0000-7000-8000-999999999999",
			wantRun:   true,
			wantOK:    false,
			contains:  []string{"TEMPORAL_NAMESPACE=0198f4d2-0000-7000-8000-999999999999", "!= resolved " + resolved.id},
		},
		{
			name:     "tenant id mismatch",
			tenantID: "not-the-tenant",
			wantRun:  true,
			wantOK:   false,
			contains: []string{"PYCK_API_TENANT_ID=not-the-tenant", "!= resolved " + resolved.id},
		},
		{
			name:      "both mismatch are both reported",
			namespace: "wrong-ns",
			tenantID:  "wrong-id",
			wantRun:   true,
			wantOK:    false,
			contains:  []string{"TEMPORAL_NAMESPACE=wrong-ns", "PYCK_API_TENANT_ID=wrong-id"},
		},
		{
			name:      "case differences are not a mismatch",
			namespace: strings.ToUpper(resolved.id),
			wantRun:   true,
			wantOK:    true,
			contains:  []string{"== TEMPORAL_NAMESPACE"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ran := crossCheck(testTarget, resolved, Options{
				TemporalNamespace: tc.namespace,
				ExpectedTenantID:  tc.tenantID,
			})

			if ran != tc.wantRun {
				t.Fatalf("ran = %v, want %v", ran, tc.wantRun)
			}

			if !ran {
				return
			}

			if got.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v (detail %q)", got.OK, tc.wantOK, got.Detail)
			}

			if got.Stage != "tenant" {
				t.Errorf("Stage = %q, want tenant", got.Stage)
			}

			for _, want := range tc.contains {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("detail %q does not contain %q", got.Detail, want)
				}
			}
		})
	}
}

func TestTenantDetail(t *testing.T) {
	tests := []struct {
		name string
		in   tenant
		want string
	}{
		{
			name: "with name",
			in:   tenant{id: "abc", name: "acme", via: viaAPI},
			want: `abc "acme" via=api`,
		},
		{
			name: "without name",
			in:   tenant{id: "abc", via: viaJWTClaim},
			want: "abc via=jwt-claim",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tenantDetail(tc.in); got != tc.want {
				t.Errorf("tenantDetail() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPyckStagesSilentWithoutToken(t *testing.T) {
	if got := pyckStages(t.Context(), testTarget, Options{}); got != nil {
		t.Errorf("got %d results, want none: no credential means no stage", len(got))
	}
}
