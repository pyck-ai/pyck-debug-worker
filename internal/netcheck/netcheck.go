// Package netcheck measures long-term connection quality to a fixed set of
// hosts: short TCP+TLS connections every 10s and one long-lived HTTP/2
// connection pinged every second, per resolved (host, IP) target. Results are
// aggregated per minute, printed as ok/FAIL lines, written to one JSON-lines
// file per UTC day and, optionally, uploaded once a day is finished.
//
// Nothing here affects the process exit code.
package netcheck

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
)

// DefaultHosts is the --netcheck-hosts default.
const DefaultHosts = "dev.pyck.cloud"

// Dir is the directory, relative to the working directory, the daily files
// are written to.
const Dir = "netcheck"

// port is the TLS port every target is measured on.
const port = 443

// errHosts marks a rejected --netcheck-hosts value.
var errHosts = errors.New("--netcheck-hosts")

// Config is the effective netcheck configuration.
type Config struct {
	// Hosts are the validated --netcheck-hosts entries.
	Hosts []string
	// Upload enables the daily upload of finished files.
	Upload bool
	// Dir is where the daily files go.
	Dir string
	// Version is the build identity written into every file header.
	Version string
	// Roots are the trust anchors hostname targets are verified against. Nil
	// means the system roots; tests inject their own pool.
	Roots *x509.CertPool
}

// ParseHosts validates a comma-separated --netcheck-hosts value. Full URLs,
// ports, empty entries and duplicates are refused; a bare IP is accepted.
func ParseHosts(value string) ([]string, error) {
	var (
		hosts []string
		seen  = map[string]bool{}
	)

	for entry := range strings.SplitSeq(value, ",") {
		host := strings.ToLower(strings.TrimSpace(entry))

		if host == "" {
			return nil, fmt.Errorf("%w: empty entry in %q", errHosts, value)
		}

		if addr, err := netip.ParseAddr(host); err == nil {
			host = addr.String()
		} else if strings.ContainsAny(host, "/:") {
			return nil, fmt.Errorf("%w: %q is not a hostname: pass the bare host, no URL, scheme, path or port",
				errHosts, entry)
		}

		if seen[host] {
			return nil, fmt.Errorf("%w: %q is listed twice", errHosts, host)
		}

		seen[host] = true
		hosts = append(hosts, host)
	}

	return hosts, nil
}

// Target is one measured (host, IP) pair.
type Target struct {
	Host string
	IP   netip.Addr
	// Port is always 443 in production; tests point it at a local listener.
	Port uint16
	// roots verifies the certificate of a hostname target; nil is the system
	// pool. A bare-IP target is never verified.
	roots *x509.CertPool
}

// Label renders the target for stdout: host/IP, or just the IP for a bare-IP
// entry.
func (t Target) Label() string {
	if t.bareIP() {
		return t.IP.String()
	}

	return t.Host + "/" + t.IP.String()
}

// addr is the dial address.
func (t Target) addr() string {
	return netip.AddrPortFrom(t.IP, t.Port).String()
}

// bareIP reports whether the target came from a bare-IP entry. Such targets
// send no SNI.
func (t Target) bareIP() bool {
	return t.Host == t.IP.String()
}

// serverName is the TLS SNI: the host, or none for a bare IP.
func (t Target) serverName() string {
	if t.bareIP() {
		return ""
	}

	return t.Host
}

// Failure classes.
const (
	classTimeout = "timeout"
	classRefused = "refused"
	classReset   = "reset"
	classOther   = "other"
	// classIntercepted is a handshake that completed far enough to present a
	// certificate that does not verify for the host: a middlebox answering in
	// the server's place, or a broken server certificate.
	classIntercepted = "intercepted"
)

// interception describes the certificate that failed verification.
type interception struct {
	Fingerprint string // hex SHA-256 of the leaf
	Issuer      string // leaf issuer CN
	Err         string // verification error
}

// interceptedError is a handshake error that carries the offending
// certificate.
type interceptedError struct {
	info interception
	err  error
}

func (e *interceptedError) Error() string { return e.err.Error() }
func (e *interceptedError) Unwrap() error { return e.err }

// wrapHandshake turns a certificate verification failure into an
// interceptedError. Any other error passes through unchanged.
func wrapHandshake(err error) error {
	var verify *tls.CertificateVerificationError
	if !errors.As(err, &verify) {
		return err
	}

	info := interception{Err: verify.Err.Error()}

	if len(verify.UnverifiedCertificates) > 0 {
		leaf := verify.UnverifiedCertificates[0]
		sum := sha256.Sum256(leaf.Raw)
		info.Fingerprint = hex.EncodeToString(sum[:])
		info.Issuer = leaf.Issuer.CommonName

		if info.Issuer == "" {
			info.Issuer = leaf.Issuer.String()
		}
	}

	return &interceptedError{info: info, err: err}
}

// interceptionOf extracts the certificate details from err, if it is one.
func interceptionOf(err error) (interception, bool) {
	var ie *interceptedError
	if errors.As(err, &ie) {
		return ie.info, true
	}

	return interception{}, false
}

// classify maps a connect or handshake error onto timeout/refused/reset/other.
// The string fallbacks cover Windows, whose socket errors do not match the
// syscall constants.
func classify(err error) string {
	var netErr net.Error

	if _, ok := interceptionOf(err); ok {
		return classIntercepted
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, syscall.ETIMEDOUT), errors.As(err, &netErr) && netErr.Timeout():
		return classTimeout
	case errors.Is(err, syscall.ECONNREFUSED), strings.Contains(err.Error(), "refused"):
		return classRefused
	case errors.Is(err, syscall.ECONNRESET), strings.Contains(err.Error(), "reset by peer"),
		strings.Contains(err.Error(), "forcibly closed"):
		return classReset
	}

	return classOther
}

// printer serialises result lines onto the shared stdout.
type printer struct {
	mu  sync.Mutex
	out io.Writer
}

// line prints one ok/FAIL line in the shared result format.
func (p *printer) line(ts time.Time, label, stage string, ok bool, dur time.Duration, detail string) {
	line := report.Result{Ts: ts, Target: label, Stage: stage, OK: ok, Duration: dur, Detail: detail}.Line()

	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Fprintln(p.out, line)
}

// Run measures until ctx is cancelled, then flushes and closes the day file.
// It never returns an error: every problem is reported as a FAIL line.
func Run(ctx context.Context, cfg Config, out io.Writer) {
	p := &printer{out: out}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	store := newStore(cfg.Dir, header{
		Type:     "header",
		Version:  cfg.Version,
		Hostname: hostname,
		OS:       osName(),
		Flags:    headerFlags{Hosts: cfg.Hosts, Upload: cfg.Upload},
	})
	defer store.close()

	agg := newAgg()

	var wg sync.WaitGroup

	for _, host := range cfg.Hosts {
		wg.Go(func() { resolveLoop(ctx, host, cfg.Roots, agg, store, p) })
	}

	if cfg.Upload {
		wg.Go(func() { uploadLoop(ctx, store, hostname, p) })
	}

	minuteLoop(ctx, agg, store, p)
	wg.Wait()
}

// minuteLoop flushes the aggregates at every UTC minute boundary.
func minuteLoop(ctx context.Context, agg *agg, store *store, p *printer) {
	for {
		next := time.Now().UTC().Truncate(time.Minute).Add(time.Minute)

		timer := time.NewTimer(time.Until(next))

		select {
		case <-ctx.Done():
			timer.Stop()

			return
		case <-timer.C:
		}

		flushMinute(agg, store, p, next.Add(-time.Minute))
	}
}

// flushMinute writes and prints one minute's aggregates.
func flushMinute(agg *agg, store *store, p *printer, minute time.Time) {
	var failed error

	for _, rec := range agg.flush(minute) {
		if err := store.write(rec.TS, rec); err != nil && failed == nil {
			failed = err
		}

		p.line(rec.TS, rec.label(), "nc-"+rec.Mode, rec.ok(), rec.duration(), rec.detail())
	}

	if err := store.flush(minute.Add(time.Minute)); err != nil && failed == nil {
		failed = err
	}

	if failed != nil {
		p.line(time.Now(), store.dir, "nc-store", false, 0, failed.Error())
	}
}
