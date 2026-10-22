package netcheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Throughput download.
const (
	// payloadPath is the 1 MiB file every host serves.
	payloadPath = "/static/netcheck/1m.bin"
	// payloadSize is its exact size.
	payloadSize = 1 << 20
	// tputInterval is how often each target downloads it.
	tputInterval = 15 * time.Minute
	// headSize is how much of a wrong body is kept to recognise a block page.
	headSize = 64 << 10
	// maxHint bounds the block-page hint.
	maxHint = 80
)

// tputTimeout bounds one download: 1 MiB at 30 kbit/s. A variable only so
// the tests can run fast.
var tputTimeout = 5 * time.Minute

// Throughput failure classes beyond the connection ones.
const (
	// classStatus is a response other than 200.
	classStatus = "status"
	// classSize is a body that is not exactly payloadSize bytes.
	classSize = "size"
)

// modeThroughput names the download in intercepted events and stdout.
const modeThroughput = "throughput"

// tputRecord is one download.
type tputRecord struct {
	Type   string    `json:"type"`
	TS     time.Time `json:"ts"`
	Host   string    `json:"host"`
	IP     string    `json:"ip"`
	OK     bool      `json:"ok"`
	Status int       `json:"status,omitempty"`
	Proto  string    `json:"proto,omitempty"`
	Bytes  int64     `json:"bytes"`
	// ConnectMS and TLSMS are the connection setup, TTFBMS from the request
	// being written to the first response byte, BodyMS from there to the
	// end of the body.
	ConnectMS float64 `json:"connect_ms,omitempty"`
	TLSMS     float64 `json:"tls_ms,omitempty"`
	TTFBMS    float64 `json:"ttfb_ms,omitempty"`
	BodyMS    float64 `json:"body_ms,omitempty"`
	// Mbps is the body's bytes over BodyMS, in Mbit/s.
	Mbps float64 `json:"mbit_s,omitempty"`
	// StallMS is the longest wait for the next piece of the body.
	StallMS float64 `json:"stall_ms,omitempty"`
	// Server is the response's Server header; BlockHint a short excerpt
	// when a wrong body looks like an HTML block page.
	Server    string `json:"server,omitempty"`
	BlockHint string `json:"block_hint,omitempty"`
	// Class is why the measurement failed: timeout, refused, reset, other,
	// intercepted, status or size. Phase is set for a reset.
	Class string    `json:"class,omitempty"`
	Phase string    `json:"phase,omitempty"`
	Error string    `json:"error,omitempty"`
	Cert  *certInfo `json:"intercepted_cert,omitempty"`

	target Target
	took   time.Duration
}

// detail is the stdout detail column.
func (r tputRecord) detail() string {
	var parts []string

	if r.Class != "" {
		fail := "fail=" + r.Class
		if r.Phase != "" {
			fail += " (" + r.Phase + ")"
		}

		parts = append(parts, fail)
	}

	if r.Status != 0 {
		parts = append(parts, fmt.Sprintf("status %d %s", r.Status, r.Proto))
	}

	parts = append(parts, fmt.Sprintf("%d B %.2f Mbit/s", r.Bytes, r.Mbps),
		fmt.Sprintf("connect %.1fms tls %.1fms ttfb %.1fms stall %.1fms", r.ConnectMS, r.TLSMS, r.TTFBMS, r.StallMS))

	if r.Server != "" {
		parts = append(parts, fmt.Sprintf("server %q", r.Server))
	}

	if r.BlockHint != "" {
		parts = append(parts, fmt.Sprintf("block page %q", r.BlockHint))
	}

	if r.Cert != nil {
		parts = append(parts, fmt.Sprintf("intercepted issuer %q sha256 %.16s…", r.Cert.Issuer, r.Cert.Fingerprint))
	}

	if r.Error != "" && r.Class != classStatus && r.Class != classSize && r.Class != classIntercepted {
		parts = append(parts, r.Error)
	}

	return strings.Join(parts, "  ")
}

// tputLoop downloads the payload from t at startup and every tputInterval.
// sh.tput serialises downloads across targets so they do not share
// bandwidth.
func tputLoop(ctx context.Context, t Target, sh *shared) {
	ticker := time.NewTicker(tputInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case sh.tput <- struct{}{}:
		}

		rec := download(ctx, t)

		<-sh.tput

		if ctx.Err() != nil {
			return
		}

		_ = sh.store.write(rec.TS, rec)

		if rec.Cert != nil {
			noteInterception(sh.agg, sh.store, t, modeThroughput,
				interception{Fingerprint: rec.Cert.Fingerprint, Issuer: rec.Cert.Issuer, Err: rec.Cert.Error})
		}

		sh.p.line(rec.TS, t.Label(), "nc-tput", rec.OK, rec.took, rec.detail())

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tputTiming collects the trace callbacks, which run on transport
// goroutines.
type tputTiming struct {
	mu                                     sync.Mutex
	connStart, connDone, tlsStart, tlsDone time.Time
	wrote, firstByte                       time.Time
	conn                                   *countConn
}

func (tt *tputTiming) set(field *time.Time) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	*field = time.Now()
}

// download fetches the payload from t, dialled to t's IP with the host as SNI
// and Host. A certificate that fails verification marks the measurement
// intercepted but does not stop it, so a block page behind it is seen.
func download(ctx context.Context, t Target) tputRecord {
	ctx, cancel := context.WithTimeout(ctx, tputTimeout)
	defer cancel()

	rec := tputRecord{Type: "throughput", TS: time.Now().UTC(), Host: t.Host, IP: t.IP.String(), target: t}
	started := time.Now()

	var (
		tt        tputTiming
		icptMu    sync.Mutex
		icpt      *interception
		dialer    net.Dialer
		authority = t.Host
	)

	if t.Port != port {
		authority = net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
	}

	cfg := tlsConfig(t)
	if !t.bareIP() {
		cfg = verifyButContinue(t.Host, t.roots, func(info interception) {
			icptMu.Lock()
			defer icptMu.Unlock()

			icpt = &info
		})
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, "tcp", t.addr())
			if err != nil {
				return nil, err
			}

			counted := &countConn{Conn: conn}

			tt.mu.Lock()
			tt.conn = counted
			tt.mu.Unlock()

			return counted, nil
		},
		TLSClientConfig:    cfg,
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		DisableKeepAlives:  true,
	}
	defer transport.CloseIdleConnections()

	trace := &httptrace.ClientTrace{
		ConnectStart:         func(string, string) { tt.set(&tt.connStart) },
		ConnectDone:          func(string, string, error) { tt.set(&tt.connDone) },
		TLSHandshakeStart:    func() { tt.set(&tt.tlsStart) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tt.set(&tt.tlsDone) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { tt.set(&tt.wrote) },
		GotFirstResponseByte: func() { tt.set(&tt.firstByte) },
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet,
		"https://"+authority+payloadPath, nil)
	if err != nil {
		rec.Class, rec.Error = classOther, err.Error()

		return rec
	}

	req.Header.Set("Accept-Encoding", "identity")

	resp, err := transport.RoundTrip(req)

	var (
		head    []byte
		stall   time.Duration
		bodyEnd time.Time
	)

	if err == nil {
		head, stall, bodyEnd, err = readBody(resp.Body, &rec)
		_ = resp.Body.Close()

		rec.Status, rec.Proto, rec.Server = resp.StatusCode, resp.Proto, resp.Header.Get("Server")
	}

	rec.took = time.Since(started)

	tt.mu.Lock()
	rec.ConnectMS = spanMS(tt.connStart, tt.connDone)
	rec.TLSMS = spanMS(tt.tlsStart, tt.tlsDone)
	rec.TTFBMS = spanMS(tt.wrote, tt.firstByte)
	rec.BodyMS = spanMS(tt.firstByte, bodyEnd)
	conn := tt.conn
	tt.mu.Unlock()

	rec.StallMS = round(ms(stall))

	if rec.BodyMS > 0 {
		rec.Mbps = round(float64(rec.Bytes) * 8 / (rec.BodyMS / 1000) / 1e6)
	}

	icptMu.Lock()
	if icpt != nil {
		rec.Cert = &certInfo{Fingerprint: icpt.Fingerprint, Issuer: icpt.Issuer, Error: icpt.Err}
	}
	icptMu.Unlock()

	failed(&rec, err, conn, head)

	return rec
}

// failed sets the failure class, if any, and judges the body.
func failed(rec *tputRecord, err error, conn *countConn, head []byte) {
	switch {
	case err != nil:
		if conn != nil {
			phase := phaseTransfer
			if conn.read.Load() == 0 {
				phase = phaseHello
			}

			err = withPhase(err, phase)
		}

		rec.Class, rec.Phase, rec.Error = classify(err), phaseOf(err), err.Error()
	case rec.Cert != nil:
		rec.Class, rec.Error = classIntercepted, rec.Cert.Error
	case rec.Status != http.StatusOK:
		rec.Class, rec.Error = classStatus, fmt.Sprintf("status %d", rec.Status)
	case rec.Bytes != payloadSize:
		rec.Class, rec.Error = classSize, fmt.Sprintf("body %d bytes, want %d", rec.Bytes, payloadSize)
	}

	rec.OK = rec.Class == ""

	if !rec.OK {
		rec.BlockHint = blockHint(head)
	}
}

// readBody reads up to one byte more than the payload, counting bytes and the
// longest wait between reads, and keeps the start of the body.
func readBody(body io.Reader, rec *tputRecord) ([]byte, time.Duration, time.Time, error) {
	var (
		head  []byte
		stall time.Duration
		buf   = make([]byte, 32<<10)
		last  = time.Now()
		limit = io.LimitReader(body, payloadSize+1)
	)

	for {
		n, err := limit.Read(buf)
		now := time.Now()

		if n > 0 {
			stall = max(stall, now.Sub(last))
			last = now
			rec.Bytes += int64(n)

			if len(head) < headSize {
				head = append(head, buf[:min(n, headSize-len(head))]...)
			}
		}

		if errors.Is(err, io.EOF) {
			return head, stall, now, nil
		}

		if err != nil {
			return head, stall, now, err
		}
	}
}

// spanMS is to-from in milliseconds, or 0 if either is unset.
func spanMS(from, to time.Time) float64 {
	if from.IsZero() || to.IsZero() {
		return 0
	}

	return round(ms(to.Sub(from)))
}

// verifyButContinue verifies the certificate for host against roots (nil:
// the system pool) like crypto/tls would, but reports a failure to onFail
// instead of aborting the handshake.
func verifyButContinue(host string, roots *x509.CertPool, onFail func(interception)) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection, a failure is recorded
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return nil
			}

			opts := x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: x509.NewCertPool()}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}

			if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
				info, _ := interceptionOf(wrapHandshake(&tls.CertificateVerificationError{
					UnverifiedCertificates: cs.PeerCertificates, Err: err,
				}))
				onFail(info)
			}

			return nil
		},
	}
}

// titleRe finds an HTML title.
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// blockHint is a short excerpt when body looks like an HTML block page: its
// title, flagged when it mentions a web filter.
func blockHint(body []byte) string {
	lower := bytes.ToLower(body)
	filter := bytes.Contains(lower, []byte("web filter"))

	if !filter && !bytes.Contains(lower, []byte("<html")) {
		return ""
	}

	hint := "html"
	if m := titleRe.FindSubmatch(body); m != nil {
		if title := strings.Join(strings.Fields(string(m[1])), " "); title != "" {
			hint = title
		}
	}

	if filter && !strings.Contains(strings.ToLower(hint), "web filter") {
		hint = "Web Filter: " + hint
	}

	hint = strings.ToValidUTF8(hint, "")
	if utf8.RuneCountInString(hint) > maxHint {
		hint = string([]rune(hint)[:maxHint]) + "…"
	}

	return hint
}
