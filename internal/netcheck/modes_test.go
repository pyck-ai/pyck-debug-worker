package netcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// testCert issues a certificate for "localhost" from a fresh test CA and
// returns the CA's pool, which listen puts on every target.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	ca := newTestCA(t, "Test CA")

	return ca.issue(t, "localhost"), ca.pool
}

// listen opens a loopback listener and returns it with the matching target,
// verifying against roots (nil: the system pool).
func listen(t *testing.T, roots *x509.CertPool) (*net.TCPListener, Target) {
	t.Helper()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln.Close() })

	addr := netip.MustParseAddrPort(ln.Addr().String())

	return ln, Target{Host: "localhost", IP: addr.Addr(), Port: addr.Port(), roots: roots}
}

// serve runs handle for every accepted connection.
func serve(ln *net.TCPListener, handle func(*net.TCPConn)) {
	go func() {
		for {
			conn, err := ln.AcceptTCP()
			if err != nil {
				return
			}

			go handle(conn)
		}
	}()
}

// reset aborts conn with a TCP RST.
func reset(conn *net.TCPConn) {
	_ = conn.SetLinger(0)
	_ = conn.Close()
}

func TestShortOnce(t *testing.T) {
	cert, roots := testCert(t)

	t.Run("handshake", func(t *testing.T) {
		ln, target := listen(t, roots)
		serve(ln, func(conn *net.TCPConn) {
			server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			_ = server.Handshake()
			_, _ = io.Copy(io.Discard, server)
		})

		r := shortOnce(context.Background(), target)
		if r.class != "" || r.connect <= 0 || r.handshake <= 0 {
			t.Errorf("shortOnce = %+v, want a completed handshake", r)
		}
	})

	t.Run("refused", func(t *testing.T) {
		ln, target := listen(t, roots)
		_ = ln.Close()

		if r := shortOnce(context.Background(), target); r.class != classRefused {
			t.Errorf("class = %q (%v), want %q", r.class, r.err, classRefused)
		}
	})

	t.Run("reset during handshake", func(t *testing.T) {
		ln, target := listen(t, roots)
		serve(ln, reset)

		if r := shortOnce(context.Background(), target); r.class != classReset {
			t.Errorf("class = %q (%v), want %q", r.class, r.err, classReset)
		}
	})
}

// pingServer is a minimal HTTP/2 server: it answers PINGs until it has seen
// after of them, then ends the connection with finish. after < 0 never ends.
func pingServer(t *testing.T, cert tls.Certificate, roots *x509.CertPool, answer bool, after int, finish func(*net.TCPConn, *http2.Framer)) Target {
	t.Helper()

	ln, target := listen(t, roots)
	serve(ln, func(conn *net.TCPConn) {
		defer conn.Close()

		server := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{http2.NextProtoTLS},
			MinVersion:   tls.VersionTLS12,
		})

		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(server, preface); err != nil {
			return
		}

		framer := http2.NewFramer(server, server)
		if err := framer.WriteSettings(); err != nil {
			return
		}

		pings := 0

		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				return
			}

			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = framer.WriteSettingsAck()
				}
			case *http2.PingFrame:
				pings++

				if after >= 0 && pings > after {
					finish(conn, framer)

					return
				}

				if answer {
					_ = framer.WritePing(true, f.Data)
				}
			}
		}
	})

	return target
}

// fastLong shortens the long-connection timing for the test.
func fastLong(t *testing.T) {
	t.Helper()

	old := []time.Duration{pingInterval, pingTimeout, deadAfter}
	pingInterval, pingTimeout, deadAfter = 20*time.Millisecond, 100*time.Millisecond, 300*time.Millisecond

	t.Cleanup(func() { pingInterval, pingTimeout, deadAfter = old[0], old[1], old[2] })
}

// runSession dials target and runs one session to its end.
func runSession(t *testing.T, target Target) (aggregate, event) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialLong(ctx, target)
	if err != nil {
		t.Fatalf("dialLong: %v", err)
	}

	a := newAgg()
	a.register(target)

	ev, ok := session(ctx, target, conn, a)
	if !ok {
		t.Fatal("session did not end before the test timeout")
	}

	return a.flush(testMinute)[1], ev
}

func TestLongSession(t *testing.T) {
	fastLong(t)

	cert, roots := testCert(t)

	t.Run("killed connection is a drop", func(t *testing.T) {
		target := pingServer(t, cert, roots, true, 5, func(conn *net.TCPConn, _ *http2.Framer) { reset(conn) })

		long, ev := runSession(t, target)

		if ev.Event != eventDrop || ev.Error == "" || ev.LifetimeS <= 0 || ev.Mode != modeLong {
			t.Errorf("event = %+v, want a drop with lifetime and error", ev)
		}

		if long.Drops != 1 || long.RTT == nil || long.Samples < 5 || long.ok() {
			t.Errorf("aggregate = %+v, want 1 drop, >=5 answered pings, FAIL", long)
		}
	})

	t.Run("GOAWAY is server-closed, not a drop", func(t *testing.T) {
		target := pingServer(t, cert, roots, true, 3, func(_ *net.TCPConn, framer *http2.Framer) {
			_ = framer.WriteGoAway(0, http2.ErrCodeNo, nil)
			time.Sleep(50 * time.Millisecond)
		})

		long, ev := runSession(t, target)

		if ev.Event != eventServerClosed {
			t.Errorf("event = %+v, want server-closed", ev)
		}

		if long.Drops != 0 || long.ServerClosed != 1 || !long.ok() {
			t.Errorf("aggregate = %+v, want server_closed=1 and ok", long)
		}
	})

	t.Run("unanswered pings are losses, then a drop", func(t *testing.T) {
		target := pingServer(t, cert, roots, false, -1, nil)

		long, ev := runSession(t, target)

		if ev.Event != eventDrop || long.Losses == 0 || long.RTT != nil {
			t.Errorf("event %+v aggregate %+v, want lost pings and a drop", ev, long)
		}
	})
}
