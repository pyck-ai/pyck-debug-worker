package probe

import (
	"net/netip"
	"testing"

	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

func TestDNSStageIPLiteralDoesNotResolve(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		family string
		want   string
	}{
		{name: "ipv4", host: "127.0.0.1", family: "ip4", want: "127.0.0.1"},
		{name: "ipv6", host: "::1", family: "ip6", want: "::1"},
		{
			// A mapped literal must come back unmapped, or the tcp stage dials
			// it over tcp6 and gets "no suitable address found".
			name: "ipv4-mapped", host: "::ffff:127.0.0.1", family: "ip4", want: "127.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tgt := target.Target{Host: tc.host, Port: 443, Kind: target.KindGRPC}

			addrs, results := dnsStage(t.Context(), tgt, Options{})
			if len(results) != 0 {
				t.Errorf("got %d results, want none: an IP literal resolves nothing", len(results))
			}

			if len(addrs) != 1 || len(addrs[0].addrs) != 1 {
				t.Fatalf("got %v, want exactly one address", addrs)
			}

			if addrs[0].family != tc.family {
				t.Errorf("family = %q, want %q", addrs[0].family, tc.family)
			}

			if got := addrs[0].addrs[0].String(); got != tc.want {
				t.Errorf("addr = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFamilyOf(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "127.0.0.1", want: "ip4"},
		{in: "::1", want: "ip6"},
		{in: "2001:db8::1", want: "ip6"},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := familyOf(netip.MustParseAddr(tc.in)); got != tc.want {
				t.Errorf("familyOf(%s) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
