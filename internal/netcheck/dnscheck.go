package netcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dohResolver is a DNS-over-HTTPS resolver the system resolver's answer is
// compared against. Queries are RFC 8484 GET requests carrying a wire-format
// message; the URL host is an IP, so no DNS is needed to reach it, and the
// certificate is verified for that IP.
type dohResolver struct {
	name string
	url  string
}

// dohResolvers are AliDNS (inside China) and Cloudflare (outside).
var dohResolvers = []dohResolver{
	{name: "alidns", url: "https://223.5.5.5/dns-query"},
	{name: "cloudflare", url: "https://1.1.1.1/dns-query"},
}

// resolverSystem names the system resolver in a DNS check.
const resolverSystem = "system"

// maxDNSResponse bounds a DoH response body.
const maxDNSResponse = 64 << 10

// errRcode is a DNS answer with an error rcode other than NXDOMAIN.
var errRcode = errors.New("dns rcode")

// errDoHStatus is a DoH response that is not 200.
var errDoHStatus = errors.New("doh status")

// dnsChecker runs the DNS check of a host.
type dnsChecker struct {
	client    *http.Client
	resolvers []dohResolver
}

// newDNSChecker queries dohResolvers, verifying against roots (nil: the
// system pool). Every query is a fresh connection, directly, never through a
// proxy, so its time is the full cost of a DoH lookup from here.
func newDNSChecker(roots *x509.CertPool) dnsChecker {
	return dnsChecker{
		client: &http.Client{
			Timeout: resolveTimeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2: true,
				DisableKeepAlives: true,
			},
		},
		resolvers: dohResolvers,
	}
}

// dnsAnswer is one resolver's answer for a host.
type dnsAnswer struct {
	Resolver string   `json:"resolver"`
	MS       float64  `json:"ms"`
	IPs      []string `json:"ips"`
	// NXDomain is an authoritative "no such name": an answer, not an error.
	NXDomain bool `json:"nxdomain,omitempty"`
	// Error and Class are set when the resolver could not be asked.
	Error string `json:"error,omitempty"`
	Class string `json:"class,omitempty"`
}

// dnsRecord is one DNS check of a host: the system resolver and every DoH
// resolver, every 5 minutes.
type dnsRecord struct {
	Type    string      `json:"type"`
	TS      time.Time   `json:"ts"`
	Host    string      `json:"host"`
	Answers []dnsAnswer `json:"answers"`
	// Mismatch is set when the resolvers that answered disagree on the set
	// of A records.
	Mismatch bool `json:"mismatch"`
	// Unreachable lists the resolvers that could not be asked.
	Unreachable []string `json:"unreachable,omitempty"`
}

// ok is false on a mismatch or an unreachable resolver.
func (r dnsRecord) ok() bool {
	return !r.Mismatch && len(r.Unreachable) == 0
}

// detail is the stdout detail column.
func (r dnsRecord) detail() string {
	parts := make([]string, 0, len(r.Answers)+1)

	if r.Mismatch {
		parts = append(parts, "mismatch")
	}

	for _, a := range r.Answers {
		switch {
		case a.Error != "":
			parts = append(parts, fmt.Sprintf("%s unreachable (%s) %.1fms", a.Resolver, a.Class, a.MS))
		case a.NXDomain:
			parts = append(parts, fmt.Sprintf("%s NXDOMAIN %.1fms", a.Resolver, a.MS))
		default:
			parts = append(parts, fmt.Sprintf("%s %s %.1fms", a.Resolver, strings.Join(a.IPs, ","), a.MS))
		}
	}

	return strings.Join(parts, "  ")
}

// systemAnswer turns the resolve loop's own lookup into the check's system
// answer.
func systemAnswer(ips []netip.Addr, err error, took time.Duration) dnsAnswer {
	a := dnsAnswer{Resolver: resolverSystem, MS: round(ms(took)), IPs: []string{}}

	var dnsErr *net.DNSError

	switch {
	case err == nil:
		for _, ip := range ips {
			a.IPs = append(a.IPs, ip.String())
		}
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		a.NXDomain = true
	default:
		a.Error, a.Class = err.Error(), classify(err)
	}

	slices.Sort(a.IPs)

	return a
}

// check asks every DoH resolver for host's A records, concurrently, and
// compares them with the system answer.
func (c dnsChecker) check(ctx context.Context, host string, system dnsAnswer) dnsRecord {
	rec := dnsRecord{Type: "dns", TS: time.Now().UTC(), Host: host, Answers: make([]dnsAnswer, 1+len(c.resolvers))}
	rec.Answers[0] = system

	var wg sync.WaitGroup

	for i, r := range c.resolvers {
		wg.Go(func() { rec.Answers[i+1] = c.query(ctx, r, host) })
	}

	wg.Wait()

	var first []string

	answered := false

	for _, a := range rec.Answers {
		if a.Error != "" {
			rec.Unreachable = append(rec.Unreachable, a.Resolver)

			continue
		}

		if !answered {
			first, answered = a.IPs, true
		} else if !slices.Equal(first, a.IPs) {
			rec.Mismatch = true
		}
	}

	return rec
}

// query asks one DoH resolver for host's A records.
func (c dnsChecker) query(ctx context.Context, r dohResolver, host string) dnsAnswer {
	started := time.Now()
	a := dnsAnswer{Resolver: r.name, IPs: []string{}}

	ips, nx, err := c.doh(ctx, r.url, host)
	a.MS = round(ms(time.Since(started)))

	if err != nil {
		err = wrapHandshake(err)
		a.Error, a.Class = err.Error(), classify(err)

		return a
	}

	a.NXDomain = nx

	for _, ip := range ips {
		a.IPs = append(a.IPs, ip.String())
	}

	slices.Sort(a.IPs)

	return a
}

// doh sends one RFC 8484 GET query and returns the A records of the answer,
// or that the name does not exist.
func (c dnsChecker) doh(ctx context.Context, url, host string) ([]netip.Addr, bool, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, false, fmt.Errorf("dns name %q: %w", host, err)
	}

	query, err := (&dnsmessage.Message{
		// ID 0, as RFC 8484 recommends for cache friendliness.
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		return nil, false, fmt.Errorf("dns query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		url+"?dns="+base64.RawURLEncoding.EncodeToString(query), nil)
	if err != nil {
		return nil, false, fmt.Errorf("doh request: %w", err)
	}

	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("%w %d", errDoHStatus, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSResponse))
	if err != nil {
		return nil, false, err
	}

	return parseA(body)
}

// parseA extracts the A records of a wire-format DNS response. NXDOMAIN is
// reported as such; any other error rcode is an error.
func parseA(msg []byte) ([]netip.Addr, bool, error) {
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		return nil, false, fmt.Errorf("dns response: %w", err)
	}

	switch m.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("%w %s", errRcode, m.RCode)
	}

	var ips []netip.Addr

	for _, rr := range m.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			ips = append(ips, netip.AddrFrom4(a.A))
		}
	}

	return ips, false, nil
}

// dnsEvents are the check's events: one dns-mismatch with every answer, one
// resolver-unreachable per resolver that could not be asked.
func dnsEvents(rec dnsRecord) []event {
	var out []event

	if rec.Mismatch {
		ev := newEvent(eventDNSMismatch, Target{Host: rec.Host})
		ev.Answers = map[string][]string{}

		for _, a := range rec.Answers {
			if a.Error == "" {
				ev.Answers[a.Resolver] = a.IPs
			}
		}

		out = append(out, ev)
	}

	for _, a := range rec.Answers {
		if a.Error == "" {
			continue
		}

		ev := newEvent(eventUnreachable, Target{Host: rec.Host})
		ev.Resolver, ev.Class, ev.Error = a.Resolver, a.Class, a.Error
		out = append(out, ev)
	}

	return out
}
