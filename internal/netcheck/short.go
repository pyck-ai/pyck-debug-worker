package netcheck

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Short connection timing.
const (
	// shortInterval is how often a fresh connection is opened.
	shortInterval = 10 * time.Second
	// dialTimeout bounds a TCP connect plus TLS handshake.
	dialTimeout = 10 * time.Second
)

// synRetransAfter are the connect times that imply a lost SYN: the initial
// SYN retransmit fires after ~1s, the second after ~3s in total.
var synRetransAfter = []time.Duration{time.Second, 3 * time.Second}

// shortResult is one short connection.
type shortResult struct {
	connect   time.Duration
	handshake time.Duration
	// class is empty on success.
	class string
	err   error
	// icpt is set when class is intercepted.
	icpt interception
}

// shortLoop opens a short connection every shortInterval until ctx ends.
func shortLoop(ctx context.Context, t Target, agg *agg, store *store) {
	ticker := time.NewTicker(shortInterval)
	defer ticker.Stop()

	for {
		r := shortOnce(ctx, t)

		if ctx.Err() != nil {
			return
		}

		switch r.class {
		case "":
			agg.short(t, r.connect, r.handshake, synRetrans(r.connect))
		case classIntercepted:
			// The handshake time is real even though the certificate is not.
			agg.short(t, r.connect, r.handshake, synRetrans(r.connect))
			noteInterception(agg, store, t, modeShort, r.icpt)
		default:
			agg.fail(t, modeShort, r.class)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// shortOnce connects, completes a TLS handshake and closes. No HTTP request
// is sent, so nothing reaches the server's access log.
func shortOnce(ctx context.Context, t Target) shortResult {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	started := time.Now()

	var dialer net.Dialer

	conn, err := dialer.DialContext(ctx, "tcp", t.addr())
	connect := time.Since(started)

	if err != nil {
		return shortResult{connect: connect, class: classify(err), err: err}
	}

	defer conn.Close()

	tlsConn := tls.Client(conn, tlsConfig(t, "h2", "http/1.1"))

	started = time.Now()
	err = tlsConn.HandshakeContext(ctx)
	handshake := time.Since(started)

	if err != nil {
		err = wrapHandshake(err)
		info, _ := interceptionOf(err)

		return shortResult{connect: connect, handshake: handshake, class: classify(err), err: err, icpt: info}
	}

	return shortResult{connect: connect, handshake: handshake}
}

// synRetrans counts the SYN retransmits a connect time implies.
func synRetrans(connect time.Duration) int {
	n := 0

	for _, after := range synRetransAfter {
		if connect >= after {
			n++
		}
	}

	return n
}

// tlsConfig uses the host as SNI and verifies the certificate for it against
// t.roots (nil: the system roots), so a TLS-intercepting middlebox shows up as
// a verification failure. A bare IP has no name to verify against: no SNI and
// no verification.
func tlsConfig(t Target, alpn ...string) *tls.Config {
	if t.bareIP() {
		return &tls.Config{
			NextProtos:         alpn,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // a bare IP has no name to verify
		}
	}

	return &tls.Config{
		ServerName: t.serverName(),
		RootCAs:    t.roots,
		NextProtos: alpn,
		MinVersion: tls.VersionTLS12,
	}
}

// noteInterception counts an intercepted handshake and writes an event the
// first time a target presents a bad certificate and whenever its
// fingerprint changes.
func noteInterception(agg *agg, store *store, t Target, mode string, info interception) {
	if !agg.intercepted(t, mode, info) {
		return
	}

	ev := newEvent(eventIntercepted, t)
	ev.Mode = mode
	ev.Fingerprint = info.Fingerprint
	ev.Issuer = info.Issuer
	ev.Error = info.Err
	_ = store.writeEvent(ev)
}
