package netcheck

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned starts an httptest TLS server: its certificate is self-signed,
// which is what a TLS-intercepting middlebox looks like to the system roots.
func selfSigned(t *testing.T, host string) (Target, string) {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.EnableHTTP2 = true
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	addr := netip.MustParseAddrPort(srv.Listener.Addr().String())
	sum := sha256.Sum256(srv.Certificate().Raw)

	if host == "" {
		host = addr.Addr().String()
	}

	return Target{Host: host, IP: addr.Addr(), Port: addr.Port()}, hex.EncodeToString(sum[:])
}

func TestShortIntercepted(t *testing.T) {
	t.Run("untrusted chain", func(t *testing.T) {
		target, fingerprint := selfSigned(t, "example.com")

		r := shortOnce(context.Background(), target, true)

		if r.class != classIntercepted {
			t.Fatalf("class = %q (%v), want %q", r.class, r.err, classIntercepted)
		}

		if r.icpt.Fingerprint != fingerprint || r.icpt.Issuer == "" || r.icpt.Err == "" {
			t.Errorf("interception = %+v, want fingerprint %s, an issuer and an error", r.icpt, fingerprint)
		}

		if r.handshake <= 0 || r.connect <= 0 {
			t.Errorf("handshake %s connect %s: the times must be measured anyway", r.handshake, r.connect)
		}
	})

	t.Run("hostname mismatch", func(t *testing.T) {
		cert, roots := testCert(t)
		ln, target := listen(t, roots)
		target.Host = "region-sing.pyck.cloud"

		serve(ln, func(conn *net.TCPConn) {
			server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			_ = server.Handshake()
			_ = server.Close()
		})

		r := shortOnce(context.Background(), target, true)
		if r.class != classIntercepted || !strings.Contains(r.icpt.Err, "region-sing.pyck.cloud") {
			t.Errorf("class %q interception %+v, want a hostname mismatch", r.class, r.icpt)
		}

		if r.icpt.Issuer != "Test CA" {
			t.Errorf("issuer = %q, want the issuing CA's CN", r.icpt.Issuer)
		}
	})

	t.Run("bare IP is not verified", func(t *testing.T) {
		target, _ := selfSigned(t, "")

		if r := shortOnce(context.Background(), target, true); r.class != "" {
			t.Errorf("class = %q (%v), want success: a bare IP has no name to verify", r.class, r.err)
		}
	})
}

func TestLongIntercepted(t *testing.T) {
	old := minBackoff
	minBackoff = 20 * time.Millisecond

	t.Cleanup(func() { minBackoff = old })

	target, fingerprint := selfSigned(t, "example.com")

	dir := t.TempDir()
	store := newStore(dir, testHeader())
	a := newAgg()
	a.register(target)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	longLoop(ctx, target, a, store)
	store.close()

	long := a.flush(testMinute)[1]
	if long.Failures[classIntercepted] < 2 || long.Cert == nil || long.Cert.Fingerprint != fingerprint || long.ok() {
		t.Errorf("aggregate = %+v cert %+v, want repeated interceptions, the fingerprint, FAIL", long, long.Cert)
	}

	if long.RTT != nil {
		t.Error("PINGs were sent through an intercepted connection")
	}

	var events []map[string]any

	for _, line := range readLines(t, filepath.Join(dir, time.Now().UTC().Format(dayLayout)+fileExt)) {
		if line["event"] == eventIntercepted {
			events = append(events, line)
		}
	}

	if len(events) != 1 || events[0]["fingerprint"] != fingerprint || events[0]["mode"] != modeLong {
		t.Errorf("intercepted events = %v, want exactly one (same fingerprint every retry)", events)
	}
}

func TestAggIntercepted(t *testing.T) {
	a := newAgg()
	a.register(testTarget)

	first := interception{Fingerprint: "aa", Issuer: "FortiGate CA", Err: "x509: unknown authority"}

	a.short(testTarget, 10*time.Millisecond, 20*time.Millisecond, 0)

	if !a.intercepted(testTarget, modeShort, first) {
		t.Error("first interception must be an event")
	}

	if a.intercepted(testTarget, modeLong, first) {
		t.Error("same fingerprint again (other mode) must not be an event")
	}

	if !a.intercepted(testTarget, modeShort, interception{Fingerprint: "bb", Issuer: "Other CA"}) {
		t.Error("a changed fingerprint must be an event")
	}

	got := a.flush(testMinute)
	short, long := got[0], got[1]

	if short.Samples != 1 || short.Failures[classIntercepted] != 2 || short.TLS == nil || short.Cert.Fingerprint != "bb" || short.ok() {
		t.Errorf("short = %+v cert %+v", short, short.Cert)
	}

	if long.Samples != 0 || long.Failures[classIntercepted] != 1 || long.ok() {
		t.Errorf("long = %+v", long)
	}

	if !strings.Contains(short.detail(), `fail=intercepted:2`) || !strings.Contains(short.detail(), `intercepted issuer "Other CA"`) {
		t.Errorf("detail %q lacks the interception", short.detail())
	}

	// The fingerprint memory survives the minute: same certificate next
	// minute is not a new event.
	if a.intercepted(testTarget, modeShort, interception{Fingerprint: "bb"}) {
		t.Error("unchanged fingerprint in a later minute must not be an event")
	}
}
