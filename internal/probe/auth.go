package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/secret"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// getMeQuery is read-only: it asks who the credential belongs to and writes
// nothing.
const getMeQuery = `query GetMe { me { TenantID TenantName UserID Username } }`

// graphQLPath is where the pyck gateway serves GraphQL.
const graphQLPath = "/graphql"

// getMeResponse is the GraphQL envelope. The field names match the query, so
// the tags are capitalised on purpose.
type getMeResponse struct {
	Data struct {
		Me struct {
			TenantID   string `json:"TenantID"`
			TenantName string `json:"TenantName"`
			UserID     string `json:"UserID"`
			Username   string `json:"Username"`
		} `json:"me"`
	} `json:"data"`
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

// patStages resolves an opaque token online.
//
// An opaque personal access token cannot be decoded, so the gateway is asked
// instead. That one request answers both questions — is the credential good,
// and whose is it — so auth and tenant are a single round trip rather than two.
func patStages(ctx context.Context, tgt target.Target, opts Options) []report.Result {
	endpoint := gatewayEndpoint(tgt, opts)

	var resolved tenant

	auth := stage(tgt, "auth", func() (bool, string) {
		resp, err := callGetMe(ctx, endpoint, opts.Token)
		if err != nil {
			return false, classify(err)
		}

		ok, detail := authVerdict(resp)
		if !ok {
			return false, detail
		}

		resolved = tenant{
			id:   resp.body.Data.Me.TenantID,
			name: resp.body.Data.Me.TenantName,
			via:  viaAPI,
		}

		return true, detail
	})

	results := []report.Result{auth}

	if !auth.OK {
		return results
	}

	return append(results, tenantResults(tgt, resolved, opts)...)
}

// getMeResult is a completed GetMe call.
type getMeResult struct {
	status int
	body   getMeResponse
}

// authVerdict judges a GetMe answer.
//
// A GraphQL server answers 200 with an errors array for an expired or rejected
// credential, so a status check alone would report a dead token as healthy.
func authVerdict(resp getMeResult) (bool, string) {
	if resp.status != http.StatusOK {
		return false, fmt.Sprintf("GetMe %d", resp.status)
	}

	if len(resp.body.Errors) > 0 {
		first := resp.body.Errors[0]

		detail := fmt.Sprintf("GetMe %d ", resp.status)
		if first.Extensions.Code != "" {
			detail += first.Extensions.Code + ": "
		}

		return false, detail + first.Message
	}

	return true, authDetail(resp)
}

// authDetail renders a successful GetMe.
func authDetail(resp getMeResult) string {
	user := resp.body.Data.Me.Username
	if user == "" {
		user = resp.body.Data.Me.UserID
	}

	return fmt.Sprintf("GetMe %d user=%s", resp.status, user)
}

// callGetMe posts the read-only query with the credential in the header, never
// in the URL or the body.
func callGetMe(ctx context.Context, endpoint string, token secret.Secret) (getMeResult, error) {
	payload, err := json.Marshal(map[string]string{"query": getMeQuery})
	if err != nil {
		return getMeResult{}, err
	}

	callCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return getMeResult{}, redactURLError(endpoint, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.Reveal())

	transport := &http.Transport{}
	defer transport.CloseIdleConnections()

	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return getMeResult{}, redactURLError(endpoint, err)
	}

	defer resp.Body.Close()

	var body getMeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&body); err != nil {
		return getMeResult{}, fmt.Errorf("decode GetMe response: %w", err)
	}

	return getMeResult{status: resp.StatusCode, body: body}, nil
}

// gatewayEndpoint picks the GraphQL endpoint: PYCK_GATEWAY_URL when set,
// otherwise the app domain being probed.
func gatewayEndpoint(tgt target.Target, opts Options) string {
	if opts.GatewayURL == "" {
		return (&url.URL{Scheme: "https", Host: tgt.Addr(), Path: graphQLPath}).String()
	}

	parsed, err := url.Parse(opts.GatewayURL)
	if err != nil {
		return opts.GatewayURL
	}

	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = graphQLPath
	}

	return parsed.String()
}

// redactURLError keeps credentials out of an error string. net/http embeds the
// request URL in its errors, and a URL that carries userinfo would otherwise
// end up in the detail column.
func redactURLError(endpoint string, err error) error {
	parsed, parseErr := url.Parse(endpoint)
	if parseErr != nil {
		return err
	}

	return fmt.Errorf("%s: %s", parsed.Redacted(),
		strings.ReplaceAll(err.Error(), endpoint, parsed.Redacted()))
}
