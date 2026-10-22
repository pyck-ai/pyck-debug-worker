package netcheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tputServer serves handler over TLS with cert on a loopback target that
// verifies against roots. h2 selects HTTP/2, else HTTP/1.1.
func tputServer(t *testing.T, cert tls.Certificate, roots *x509.CertPool, h2 bool, handler http.HandlerFunc) Target {
	t.Helper()

	ln, target := listen(t, roots)

	protos := []string{"http/1.1"}
	if h2 {
		protos = []string{"h2", "http/1.1"}
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: protos, MinVersion: tls.VersionTLS12},
	}

	go func() { _ = srv.ServeTLS(ln, "", "") }()

	t.Cleanup(func() { _ = srv.Close() })

	return target
}

// payload serves the 1 MiB file and checks the request.
func payload(t *testing.T) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != payloadPath || r.Header.Get("Accept-Encoding") != "identity" || !strings.HasPrefix(r.Host, "localhost") {
			t.Errorf("request %s %s Host %q Accept-Encoding %q", r.Method, r.URL, r.Host, r.Header.Get("Accept-Encoding"))
		}

		w.Header().Set("Server", "nginx")
		_, _ = w.Write(make([]byte, payloadSize))
	}
}

const blockPage = `<!DOCTYPE html><html><head><title>
  Web Filter Violation </title></head><body>FortiGuard Web Filter blocked this.</body></html>`

func TestDownload(t *testing.T) {
	cert, roots := testCert(t)

	t.Run("payload over HTTP/2", func(t *testing.T) {
		rec := download(context.Background(), tputServer(t, cert, roots, true, payload(t)))

		if !rec.OK || rec.Class != "" || rec.Status != http.StatusOK || rec.Bytes != payloadSize || rec.Proto != "HTTP/2.0" {
			t.Fatalf("record = %+v, want an ok 1 MiB HTTP/2 download", rec)
		}

		if rec.Mbps <= 0 || rec.TTFBMS <= 0 || rec.ConnectMS <= 0 || rec.TLSMS <= 0 || rec.BodyMS <= 0 || rec.Server != "nginx" {
			t.Errorf("record = %+v, want timings, throughput and the Server header", rec)
		}

		if rec.Cert != nil || rec.BlockHint != "" || rec.Type != "throughput" || rec.Host != "localhost" {
			t.Errorf("record = %+v", rec)
		}
	})

	t.Run("short body", func(t *testing.T) {
		rec := download(context.Background(), tputServer(t, cert, roots, true, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, 1000))
		}))

		if rec.OK || rec.Class != classSize || rec.Bytes != 1000 || rec.BlockHint != "" {
			t.Errorf("record = %+v, want a size failure", rec)
		}
	})

	t.Run("oversized body", func(t *testing.T) {
		rec := download(context.Background(), tputServer(t, cert, roots, true, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, 2*payloadSize))
		}))

		if rec.OK || rec.Class != classSize || rec.Bytes != payloadSize+1 {
			t.Errorf("record = %+v, want a size failure after one byte too many", rec)
		}
	})

	t.Run("block page", func(t *testing.T) {
		rec := download(context.Background(), tputServer(t, cert, roots, true, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "FortiGate")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, blockPage)
		}))

		if rec.OK || rec.Class != classStatus || rec.Status != http.StatusForbidden || rec.Server != "FortiGate" ||
			rec.BlockHint != "Web Filter Violation" {
			t.Errorf("record = %+v, want a status failure with server and block hint", rec)
		}

		if d := rec.detail(); !strings.Contains(d, `block page "Web Filter Violation"`) || !strings.Contains(d, "status 403") {
			t.Errorf("detail %q", d)
		}
	})

	t.Run("intercepted connection still downloads", func(t *testing.T) {
		other := newTestCA(t, "Other CA")
		target := tputServer(t, cert, other.pool, true, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, blockPage)
		})

		rec := download(context.Background(), target)

		if rec.OK || rec.Class != classIntercepted || rec.Cert == nil || rec.Cert.Issuer != "Test CA" || rec.Cert.Fingerprint == "" {
			t.Fatalf("record = %+v cert %+v, want intercepted with the certificate", rec, rec.Cert)
		}

		if rec.Status != http.StatusOK || rec.BlockHint != "Web Filter Violation" {
			t.Errorf("record = %+v, want the block page behind the interception", rec)
		}
	})

	t.Run("bare IP is not verified", func(t *testing.T) {
		hosts := make(chan string, 1)
		target := tputServer(t, cert, nil, true, func(w http.ResponseWriter, r *http.Request) {
			hosts <- r.Host

			_, _ = w.Write(make([]byte, payloadSize))
		})
		target.Host = target.IP.String()

		if rec := download(context.Background(), target); !rec.OK {
			t.Errorf("record = %+v, want ok: a bare IP has no name to verify", rec)
		}

		if host := <-hosts; host != target.addr() {
			t.Errorf("Host %q, want the IP %s", host, target.addr())
		}
	})

	t.Run("stall", func(t *testing.T) {
		rec := download(context.Background(), tputServer(t, cert, roots, false, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, payloadSize/2))
			w.(http.Flusher).Flush() //nolint:forcetypeassert // test server

			time.Sleep(300 * time.Millisecond)

			_, _ = w.Write(make([]byte, payloadSize/2))
		}))

		if !rec.OK || rec.StallMS < 250 || rec.Proto != "HTTP/1.1" {
			t.Errorf("record = %+v, want ok with a ~300ms stall", rec)
		}
	})

	t.Run("reset mid-transfer", func(t *testing.T) {
		rec := download(context.Background(), tputServer(t, cert, roots, false, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "1048576")
			_, _ = w.Write(make([]byte, 64<<10))
			w.(http.Flusher).Flush() //nolint:forcetypeassert // test server

			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)

				return
			}

			tcp, _ := conn.(*tls.Conn).NetConn().(*net.TCPConn) //nolint:forcetypeassert // test server
			time.Sleep(50 * time.Millisecond)
			reset(tcp)
		}))

		if rec.OK || rec.Class != classReset || rec.Phase != phaseTransfer || rec.Bytes == 0 {
			t.Errorf("record = %+v, want a reset in the transfer phase after some bytes", rec)
		}
	})

	t.Run("refused", func(t *testing.T) {
		ln, target := listen(t, roots)
		_ = ln.Close()

		if rec := download(context.Background(), target); rec.Class != classRefused || rec.Phase != "" {
			t.Errorf("record = %+v, want refused", rec)
		}
	})
}

func TestTputLoop(t *testing.T) {
	cert, roots := testCert(t)
	target := tputServer(t, cert, roots, true, payload(t))

	dir := t.TempDir()
	var out bytes.Buffer

	sh := &shared{agg: newAgg(), store: newStore(dir, testHeader()), p: &printer{out: &out}, tput: make(chan struct{}, 1)}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	tputLoop(ctx, target, sh)
	sh.store.close()

	if line := out.String(); !strings.Contains(line, "nc-tput") || !strings.Contains(line, " ok ") ||
		!strings.Contains(line, "1048576 B") {
		t.Errorf("stdout %q, want one ok nc-tput line", line)
	}

	lines := readLines(t, filepath.Join(dir, time.Now().UTC().Format(dayLayout)+fileExt))
	if len(lines) != 2 || lines[1]["type"] != "throughput" || lines[1]["ok"] != true || lines[1]["bytes"] != float64(payloadSize) {
		t.Errorf("file = %v, want the header and one throughput record", lines)
	}
}

func TestBlockHint(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{name: "binary", body: "\x00\x01garbage", want: ""},
		{name: "title", body: blockPage, want: "Web Filter Violation"},
		{name: "html without title", body: "<HTML><body>nope</body></HTML>", want: "html"},
		{name: "filter mentioned, other title", body: "<html><title>Access denied</title>FortiGuard Web Filter", want: "Web Filter: Access denied"},
		{name: "long title", body: "<html><title>" + strings.Repeat("x", 200) + "</title>", want: strings.Repeat("x", 80) + "…"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := blockHint([]byte(tc.body)); got != tc.want {
				t.Errorf("blockHint = %q, want %q", got, tc.want)
			}
		})
	}
}
