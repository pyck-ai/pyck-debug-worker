package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// tlsStage performs the handshake on the connection the tcp stage kept.
//
// Verification is deliberately disabled here and performed by the cert and
// chain stages instead. A verifying handshake aborts on the first fault, which
// would hide every later one: an expired certificate would mean no cert or
// chain Result at all. This stage therefore answers exactly one question — did
// a TLS handshake complete — and the certificate verdicts belong to the stages
// named after them.
func tlsStage(ctx context.Context, tgt target.Target, conn net.Conn) (*tls.ConnectionState, report.Result) {
	var state *tls.ConnectionState

	result := stage(tgt, "tls", func() (bool, string) {
		client := tls.Client(conn, &tls.Config{
			ServerName:         tgt.Host,
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // cert and chain stages verify explicitly
		})

		if err := client.HandshakeContext(ctx); err != nil {
			return false, classify(err)
		}

		s := client.ConnectionState()
		state = &s

		return true, tlsDetail(s)
	})

	return state, result
}

// tlsDetail renders the negotiated parameters.
func tlsDetail(s tls.ConnectionState) string {
	alpn := s.NegotiatedProtocol
	if alpn == "" {
		alpn = "none"
	}

	detail := fmt.Sprintf("%s alpn=%s %s",
		strings.ReplaceAll(tls.VersionName(s.Version), " ", ""),
		alpn,
		tls.CipherSuiteName(s.CipherSuite),
	)

	// CurveID is zero for a key exchange that used no curve (RSA under TLS 1.2).
	if s.CurveID != 0 {
		detail += " kx=" + s.CurveID.String()
	}

	return detail
}
