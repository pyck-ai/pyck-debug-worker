package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/net/http2"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// probePath is unauthenticated and 200-able on the pyck app domain.
const probePath = "/static/settings.json"

// maxBodyBytes caps how much of a response the prober reads. Nothing here needs
// the content, only its size.
const maxBodyBytes = 1 << 20

// http2Stage fetches one known-good path over HTTP/2.
//
// It uses http2.Transport rather than http.Transport, so there is no HTTP/1.1
// fallback: a server that cannot negotiate h2 fails loudly instead of silently
// downgrading. RoundTrip is called directly, so redirects are never followed —
// following one would probe an endpoint nobody asked for.
func http2Stage(ctx context.Context, tgt target.Target, opts Options) report.Result {
	return stage(tgt, "http2", func() (bool, string) {
		transport := &http2.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: tgt.Host,
				RootCAs:    opts.Roots,
				MinVersion: tls.VersionTLS12,
			},
		}
		defer transport.CloseIdleConnections()

		endpoint := url.URL{Scheme: "https", Host: tgt.Addr(), Path: probePath}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return false, classify(err)
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			return false, classify(err)
		}

		defer resp.Body.Close()

		size, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		if err != nil {
			return false, fmt.Sprintf("GET %s -> %s %s  body: %s",
				probePath, resp.Status, resp.Proto, classify(err))
		}

		detail := fmt.Sprintf("GET %s -> %s %s (%d B)", probePath, resp.Status, resp.Proto, size)

		if resp.ProtoMajor != 2 {
			return false, detail + "  not HTTP/2"
		}

		// The path is unauthenticated and 200-able by design, so anything from
		// 400 up is a real regression, not an h2 detail.
		if resp.StatusCode >= http.StatusBadRequest {
			return false, detail
		}

		return true, detail
	})
}
