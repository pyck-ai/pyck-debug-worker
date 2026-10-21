package netcheck

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Resolver timing.
const (
	// resolveInterval is how often each host's A records are refreshed.
	resolveInterval = 5 * time.Minute
	// resolveTimeout bounds one lookup.
	resolveTimeout = 10 * time.Second
)

// resolveLoop measures every A record of host, re-resolving every
// resolveInterval: a new IP starts being measured, a removed one stops (its
// data is kept). A bare-IP host is a single target and is never resolved.
func resolveLoop(ctx context.Context, host string, roots *x509.CertPool, agg *agg, store *store, p *printer) {
	running := map[netip.Addr]context.CancelFunc{}

	var wg sync.WaitGroup

	defer wg.Wait()

	apply := func(ips []netip.Addr) {
		want := map[netip.Addr]bool{}

		for _, ip := range ips {
			want[ip] = true

			if _, ok := running[ip]; ok {
				continue
			}

			t := Target{Host: host, IP: ip, Port: port, roots: roots}
			tctx, cancel := context.WithCancel(ctx)
			running[ip] = cancel

			agg.register(t)
			_ = store.writeEvent(newEvent(eventIPAdded, t))

			wg.Go(func() { shortLoop(tctx, t, agg, store) })
			wg.Go(func() { longLoop(tctx, t, agg, store) })
		}

		for ip, cancel := range running {
			if want[ip] {
				continue
			}

			t := Target{Host: host, IP: ip, Port: port, roots: roots}

			cancel()
			delete(running, ip)
			agg.unregister(t)
			_ = store.writeEvent(newEvent(eventIPRemoved, t))
		}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		apply([]netip.Addr{ip})
		<-ctx.Done()

		return
	}

	ticker := time.NewTicker(resolveInterval)
	defer ticker.Stop()

	for {
		started := time.Now()

		ips, err := lookup(ctx, host)

		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			// The current targets keep being measured: one failed lookup is
			// not a reason to stop.
			ev := newEvent(eventResolveFail, Target{Host: host})
			ev.Error = err.Error()
			_ = store.writeEvent(ev)

			p.line(started, host, "nc-dns", false, time.Since(started), err.Error())
		default:
			apply(ips)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// lookup resolves host's A records with the system resolver.
func lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}

	for i, ip := range ips {
		ips[i] = ip.Unmap()
	}

	return ips, nil
}
