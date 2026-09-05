package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// plaintextPort is the port the redirect stage probes.
const plaintextPort = "80"

// redirectStage checks what the plaintext port does with a request.
//
// Redirects are deliberately not followed: the question is what :80 answers,
// not where it eventually leads. The status code itself is not asserted —
// Traefik's `permanent` setting is left at the chart default, so 301 and 308
// are both correct.
func redirectStage(ctx context.Context, tgt target.Target) report.Result {
	return stage(tgt, "redirect", func() (bool, string) {
		endpoint := url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort(tgt.Host, plaintextPort),
			Path:   "/",
		}

		return checkRedirect(ctx, endpoint.String(), tgt.Host)
	})
}

// checkRedirect requests rawURL and judges the answer. host is the name the
// redirect is expected to stay on.
func checkRedirect(ctx context.Context, rawURL, host string) (bool, string) {
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, classify(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Nothing listening on :80 is a valid HTTPS-only deployment.
		if errors.Is(err, syscall.ECONNREFUSED) {
			return true, "no listener on :" + plaintextPort + " (connection refused)"
		}

		return false, classify(err)
	}

	defer resp.Body.Close()

	return redirectVerdict(resp, host)
}

// redirectVerdict judges a plaintext response.
func redirectVerdict(resp *http.Response, host string) (bool, string) {
	if resp.StatusCode < http.StatusMultipleChoices || resp.StatusCode >= http.StatusBadRequest {
		return false, fmt.Sprintf("%s: plaintext served in the clear, no redirect", resp.Status)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return false, fmt.Sprintf("%s: no Location header", resp.Status)
	}

	loc, err := url.Parse(location)
	if err != nil {
		return false, fmt.Sprintf("%s -> %s: unparsable Location", resp.Status, location)
	}

	switch {
	case !strings.EqualFold(loc.Scheme, "https"):
		return false, fmt.Sprintf("%s -> %s: redirect stays plaintext", resp.Status, location)
	case !strings.EqualFold(loc.Hostname(), host):
		return false, fmt.Sprintf("%s -> %s: redirect leaves %s", resp.Status, location, host)
	default:
		return true, fmt.Sprintf("%s -> %s", resp.Status, location)
	}
}
