package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// families are queried separately so an IPv6-only failure stays visible instead
// of being masked by a working A record.
var families = []string{"ip4", "ip6"}

// resolved carries one family's lookup outcome to the tcp stage.
type resolved struct {
	family string
	addrs  []netip.Addr
}

// dnsStage resolves the target host, one address family at a time.
//
// A family that simply has no record (NXDOMAIN/no data) is not a failure: an
// A-only host is the norm, and there is no WARN status to express "absent but
// fine". It is only a failure when neither family resolves, or when the lookup
// itself errors.
func dnsStage(ctx context.Context, tgt target.Target, opts Options) ([]resolved, []report.Result) {
	// An IP literal has nothing to resolve. The stage does not apply, so it
	// prints nothing rather than inventing a verdict about a lookup that never
	// happened — asking for the other family would report a false failure.
	if addr, err := netip.ParseAddr(tgt.Host); err == nil {
		addr = addr.Unmap()

		return []resolved{{family: familyOf(addr), addrs: []netip.Addr{addr}}}, nil
	}

	type lookup struct {
		addrs []netip.Addr
		err   error
	}

	lookups := make([]lookup, len(families))

	res := &net.Resolver{PreferGo: true}

	for i, family := range families {
		addrs, err := res.LookupNetIP(ctx, family, tgt.Host)

		// LookupNetIP can hand back IPv4-mapped IPv6 addresses. Left mapped,
		// they render as ::ffff:127.0.0.1 and get dialed over tcp6, which
		// fails with "no suitable address found".
		for j := range addrs {
			addrs[j] = addrs[j].Unmap()
		}

		lookups[i] = lookup{addrs: addrs, err: err}
	}

	nothingResolved := true

	for _, l := range lookups {
		if len(l.addrs) > 0 {
			nothingResolved = false
		}
	}

	var (
		out     []resolved
		results = make([]report.Result, 0, len(families))
	)

	for i, family := range families {
		l := lookups[i]

		results = append(results, stage(tgt, "dns("+family+")", func() (bool, string) {
			if l.err != nil && (nothingResolved || !notFound(l.err)) {
				return false, classify(l.err)
			}

			return true, dnsDetail(l.addrs, opts)
		}))

		if len(l.addrs) > 0 {
			out = append(out, resolved{family: family, addrs: l.addrs})
		}
	}

	return out, results
}

// dnsDetail renders the address count, the addresses and the resolver used.
func dnsDetail(addrs []netip.Addr, opts Options) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%d addrs", len(addrs))

	for _, a := range addrs {
		b.WriteString(" ")
		b.WriteString(a.String())
	}

	// PreferGo pins the pure-Go resolver, so the config in use is never the
	// cgo one regardless of platform.
	b.WriteString(" resolver=go")

	if opts.DebugDNS {
		b.WriteString(" netdns=go+1 (resolver trace on stderr)")
	}

	return b.String()
}

// notFound reports whether err is "this name has no record of that family",
// as opposed to a resolver or network failure.
func notFound(err error) bool {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return false
	}

	return dnsErr.IsNotFound
}

// familyOf names the address family the way the LookupNetIP networks do.
func familyOf(addr netip.Addr) string {
	if addr.Is4() {
		return "ip4"
	}

	return "ip6"
}
