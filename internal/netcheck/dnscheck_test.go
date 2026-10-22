package netcheck

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dohServer answers RFC 8484 GET queries: /a and /b with different A
// records, /nx with NXDOMAIN, /fail with SERVFAIL.
func dohServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil || r.Header.Get("Accept") != "application/dns-message" {
			http.Error(w, "bad query", http.StatusBadRequest)

			return
		}

		var q dnsmessage.Message
		if err := q.Unpack(raw); err != nil || len(q.Questions) != 1 || q.Questions[0].Type != dnsmessage.TypeA {
			http.Error(w, "bad message", http.StatusBadRequest)

			return
		}

		resp := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: q.Questions}

		switch r.URL.Path {
		case "/a":
			resp.Answers = []dnsmessage.Resource{aRecord(q.Questions[0].Name, 192, 0, 2, 11), aRecord(q.Questions[0].Name, 192, 0, 2, 10)}
		case "/b":
			resp.Answers = []dnsmessage.Resource{aRecord(q.Questions[0].Name, 198, 51, 100, 7)}
		case "/nx":
			resp.RCode = dnsmessage.RCodeNameError
		case "/fail":
			resp.RCode = dnsmessage.RCodeServerFailure
		}

		out, err := resp.Pack()
		if err != nil {
			t.Error(err)

			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

func aRecord(name dnsmessage.Name, a, b, c, d byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AResource{A: [4]byte{a, b, c, d}},
	}
}

// checker queries srv's paths as resolvers, trusting srv's certificate.
func checker(srv *httptest.Server, paths ...string) dnsChecker {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	c := newDNSChecker(pool)
	c.resolvers = nil

	for _, path := range paths {
		c.resolvers = append(c.resolvers, dohResolver{name: path, url: srv.URL + path})
	}

	return c
}

var systemTwo = dnsAnswer{Resolver: resolverSystem, MS: 3, IPs: []string{"192.0.2.10", "192.0.2.11"}}

func TestDNSCheck(t *testing.T) {
	srv := dohServer(t)

	t.Run("all agree", func(t *testing.T) {
		rec := checker(srv, "/a").check(context.Background(), "dev.pyck.cloud", systemTwo)

		if !rec.ok() || rec.Mismatch || len(rec.Answers) != 2 || rec.Type != "dns" || rec.Host != "dev.pyck.cloud" {
			t.Fatalf("record = %+v, want two matching answers", rec)
		}

		// Sorted, so order in the response does not matter.
		if got := rec.Answers[1]; !slices.Equal(got.IPs, systemTwo.IPs) || got.MS <= 0 || got.Resolver != "/a" {
			t.Errorf("DoH answer = %+v", got)
		}

		if events := dnsEvents(rec); len(events) != 0 {
			t.Errorf("events = %+v, want none", events)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		rec := checker(srv, "/a", "/b").check(context.Background(), "dev.pyck.cloud", systemTwo)

		if rec.ok() || !rec.Mismatch || len(rec.Unreachable) != 0 {
			t.Fatalf("record = %+v, want a mismatch", rec)
		}

		events := dnsEvents(rec)
		want := map[string][]string{resolverSystem: systemTwo.IPs, "/a": systemTwo.IPs, "/b": {"198.51.100.7"}}

		if len(events) != 1 || events[0].Event != eventDNSMismatch || !reflect.DeepEqual(events[0].Answers, want) {
			t.Errorf("events = %+v, want one dns-mismatch with %v", events, want)
		}
	})

	t.Run("NXDOMAIN is an answer, SERVFAIL is unreachable", func(t *testing.T) {
		rec := checker(srv, "/nx", "/fail").check(context.Background(), "dev.pyck.cloud", systemTwo)

		nx, fail := rec.Answers[1], rec.Answers[2]

		if !nx.NXDomain || nx.Error != "" || len(nx.IPs) != 0 {
			t.Errorf("NXDOMAIN answer = %+v", nx)
		}

		if fail.Error == "" || !slices.Equal(rec.Unreachable, []string{"/fail"}) {
			t.Errorf("SERVFAIL answer = %+v unreachable %v", fail, rec.Unreachable)
		}

		if !rec.Mismatch {
			t.Error("NXDOMAIN against two A records must be a mismatch")
		}
	})

	t.Run("unreachable resolver", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}

		closed := "https://" + ln.Addr().String() + "/dns-query"
		_ = ln.Close()

		c := checker(srv, "/a")
		c.resolvers = append(c.resolvers, dohResolver{name: "gone", url: closed})

		rec := c.check(context.Background(), "dev.pyck.cloud", systemTwo)

		if rec.ok() || rec.Mismatch || !slices.Equal(rec.Unreachable, []string{"gone"}) || rec.Answers[2].Class != classRefused {
			t.Fatalf("record = %+v, want gone unreachable (refused), no mismatch", rec)
		}

		events := dnsEvents(rec)
		if len(events) != 1 || events[0].Event != eventUnreachable || events[0].Resolver != "gone" || events[0].Class != classRefused {
			t.Errorf("events = %+v, want one resolver-unreachable", events)
		}
	})

	t.Run("untrusted resolver certificate is intercepted", func(t *testing.T) {
		c := newDNSChecker(x509.NewCertPool())
		c.resolvers = []dohResolver{{name: "a", url: srv.URL + "/a"}}

		rec := c.check(context.Background(), "dev.pyck.cloud", systemTwo)
		if got := rec.Answers[1]; got.Class != classIntercepted {
			t.Errorf("answer = %+v, want class %q", got, classIntercepted)
		}
	})
}

func TestSystemAnswer(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.11"), netip.MustParseAddr("192.0.2.10")}

	if got := systemAnswer(ips, nil, 3*time.Millisecond); !reflect.DeepEqual(got, systemTwo) {
		t.Errorf("answer = %+v, want %+v", got, systemTwo)
	}

	nx := systemAnswer(nil, &net.DNSError{Err: "no such host", IsNotFound: true}, time.Millisecond)
	if !nx.NXDomain || nx.Error != "" {
		t.Errorf("not found = %+v, want NXDOMAIN", nx)
	}

	gone := systemAnswer(nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}, time.Second)
	if gone.Error == "" || gone.Class != classTimeout {
		t.Errorf("timeout = %+v, want unreachable (timeout)", gone)
	}
}

func TestParseA(t *testing.T) {
	name := dnsmessage.MustNewName("dev.pyck.cloud.")
	cname := dnsmessage.MustNewName("alias.example.")

	msg, err := (&dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.CNAMEResource{CNAME: cname},
			},
			aRecord(cname, 192, 0, 2, 10),
		},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}

	ips, nx, err := parseA(msg)
	if err != nil || nx || !slices.Equal(ips, []netip.Addr{netip.MustParseAddr("192.0.2.10")}) {
		t.Errorf("parseA = %v %v %v, want the A record behind the CNAME", ips, nx, err)
	}

	if _, _, err := parseA([]byte{1, 2, 3}); err == nil {
		t.Error("garbage parsed")
	}

	refused, _ := (&dnsmessage.Message{Header: dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeRefused}}).Pack()
	if _, _, err := parseA(refused); !errors.Is(err, errRcode) {
		t.Errorf("REFUSED: err = %v, want errRcode", err)
	}
}
