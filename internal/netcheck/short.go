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
	// phase is set when class is reset.
	phase string
}

// shortLoop opens a short connection every shortInterval until ctx ends.
// A hostname target alternates between sending the host as SNI and sending
// none, so SNI-based blocking shows as only one variant failing.
func shortLoop(ctx context.Context, t Target, agg *agg, store *store) {
	ticker := time.NewTicker(shortInterval)
	defer ticker.Stop()

	for i := 0; ; i++ {
		withSNI := sendSNI(t, i)
		r := shortOnce(ctx, t, withSNI)

		if ctx.Err() != nil {
			return
		}

		if !t.bareIP() {
			variant := sniHost
			if !withSNI {
				variant = sniNone
			}

			agg.sni(t, variant, r.class)
		}

		if r.class == classReset {
			agg.reset(t, modeShort, r.phase)
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

// sendSNI reports whether the i-th short connection to t sends SNI: every
// other one for a hostname, never for a bare IP.
func sendSNI(t Target, i int) bool {
	return !t.bareIP() && i%2 == 0
}

// shortOnce connects, completes a TLS handshake and closes. No HTTP request
// is sent, so nothing reaches the server's access log. Without withSNI the
// handshake sends no SNI and, having no name to check, verifies nothing.
func shortOnce(ctx context.Context, t Target, withSNI bool) shortResult {
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

	cfg := tlsConfig(t, "h2", "http/1.1")
	if !withSNI {
		cfg = unverifiedTLS("h2", "http/1.1")
	}

	counted := &countConn{Conn: conn}
	tlsConn := tls.Client(counted, cfg)

	started = time.Now()
	err = tlsConn.HandshakeContext(ctx)
	handshake := time.Since(started)

	if err != nil {
		err = withPhase(wrapHandshake(err), handshakePhase(counted))
		info, _ := interceptionOf(err)

		return shortResult{
			connect: connect, handshake: handshake, class: classify(err), err: err, icpt: info, phase: phaseOf(err),
		}
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
		return unverifiedTLS(alpn...)
	}

	return &tls.Config{
		ServerName: t.serverName(),
		RootCAs:    t.roots,
		NextProtos: alpn,
		MinVersion: tls.VersionTLS12,
	}
}

// unverifiedTLS sends no SNI and verifies nothing: without a name there is
// nothing to verify the certificate against.
func unverifiedTLS(alpn ...string) *tls.Config {
	return &tls.Config{
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // no name to verify against
	}
}

// noteFailure records a failed long or idle dial: an interception, or a
// failure class plus, for a reset, its phase.
func noteFailure(agg *agg, store *store, t Target, mode string, err error) {
	if info, ok := interceptionOf(err); ok {
		noteInterception(agg, store, t, mode, info)

		return
	}

	agg.fail(t, mode, classify(err))

	if phase := phaseOf(err); phase != "" {
		agg.reset(t, mode, phase)
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
