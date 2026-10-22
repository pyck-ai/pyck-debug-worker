package netcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/http2"
)

func TestSendSNI(t *testing.T) {
	bare := Target{Host: testTarget.IP.String(), IP: testTarget.IP}

	for i, want := range []bool{true, false, true, false} {
		if got := sendSNI(testTarget, i); got != want {
			t.Errorf("sendSNI(host, %d) = %v, want %v", i, got, want)
		}

		if sendSNI(bare, i) {
			t.Errorf("sendSNI(bare IP, %d) = true: a bare IP never sends SNI", i)
		}
	}
}

// sniFilter starts a TLS server that resets every handshake whose
// ClientHello names a host, like an SNI-based firewall, and reports the SNI
// of every ClientHello it saw.
func sniFilter(t *testing.T) (Target, <-chan string) {
	t.Helper()

	cert, roots := testCert(t)
	ln, target := listen(t, roots)
	seen := make(chan string, 4)

	serve(ln, func(conn *net.TCPConn) {
		server := tls.Server(conn, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				seen <- hello.ServerName

				if hello.ServerName != "" {
					reset(conn)

					return nil, errors.New("filtered")
				}

				return nil, nil
			},
		})

		if server.Handshake() == nil {
			_, _ = io.Copy(io.Discard, server)
		}
	})

	return target, seen
}

func TestShortSNIVariants(t *testing.T) {
	target, seen := sniFilter(t)

	named := shortOnce(context.Background(), target, true)
	if named.class != classReset || named.phase != phaseHello {
		t.Errorf("with SNI: class %q phase %q (%v), want a reset right after the ClientHello", named.class, named.phase, named.err)
	}

	if sni := <-seen; sni != "localhost" {
		t.Errorf("SNI variant sent %q, want the host", sni)
	}

	none := shortOnce(context.Background(), target, false)
	if none.class != "" {
		t.Errorf("without SNI: class %q (%v), want success", none.class, none.err)
	}

	if sni := <-seen; sni != "" {
		t.Errorf("no-SNI variant sent %q", sni)
	}
}

func TestShortNoSNIIsNotIntercepted(t *testing.T) {
	// A certificate no root vouches for: intercepted with SNI, but the
	// no-SNI variant has no name to verify and must not call it that.
	target, _ := selfSigned(t, "example.com")

	if r := shortOnce(context.Background(), target, true); r.class != classIntercepted {
		t.Errorf("with SNI: class %q, want %q", r.class, classIntercepted)
	}

	if r := shortOnce(context.Background(), target, false); r.class != "" {
		t.Errorf("without SNI: class %q (%v), want success", r.class, r.err)
	}
}

func TestAggSNIAndResets(t *testing.T) {
	a := newAgg()
	a.register(testTarget)

	a.sni(testTarget, sniHost, classReset)
	a.sni(testTarget, sniHost, classReset)
	a.sni(testTarget, sniNone, "")
	a.sni(testTarget, sniNone, "")
	a.reset(testTarget, modeShort, phaseHello)
	a.reset(testTarget, modeShort, phaseHello)

	short := a.flush(testMinute)[0]

	if s := short.SNI[sniHost]; s == nil || s.Samples != 2 || s.Failures[classReset] != 2 || s.ok() != 0 {
		t.Errorf("host variant = %+v", s)
	}

	if s := short.SNI[sniNone]; s == nil || s.Samples != 2 || s.Failures != nil || s.ok() != 2 {
		t.Errorf("none variant = %+v", s)
	}

	if short.Resets[phaseHello] != 2 {
		t.Errorf("resets = %v", short.Resets)
	}

	for _, want := range []string{"resets=hello:2", "sni ok host 0/2 none 2/2"} {
		if !strings.Contains(short.detail(), want) {
			t.Errorf("detail %q lacks %q", short.detail(), want)
		}
	}
}

func TestLongResetIsTransfer(t *testing.T) {
	fastLong(t)

	cert, roots := testCert(t)
	target := pingServer(t, cert, roots, true, 3, func(conn *net.TCPConn, _ *http2.Framer) { reset(conn) })

	long, ev := runSession(t, target)

	if ev.Class != classReset || ev.Phase != phaseTransfer || long.Resets[phaseTransfer] != 1 {
		t.Errorf("event %+v resets %v, want a reset in the transfer phase", ev, long.Resets)
	}
}

func TestLongDialResetIsHello(t *testing.T) {
	target, _ := sniFilter(t)

	_, err := dialLong(context.Background(), target)
	if phaseOf(err) != phaseHello {
		t.Errorf("dialLong error %v has phase %q, want %q", err, phaseOf(err), phaseHello)
	}
}
