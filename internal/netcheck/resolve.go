package netcheck

import (
	"context"
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
// data is kept). Each resolution is followed by the DNS check. A bare-IP host
// is a single target and is never resolved.
func resolveLoop(ctx context.Context, host string, sh *shared) {
	roots, agg, store, p := sh.roots, sh.agg, sh.store, sh.p
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
			wg.Go(func() { idleLoop(tctx, t, agg, store) })
			wg.Go(func() { tputLoop(tctx, t, sh) })
			wg.Go(func() { traceLoop(tctx, t, sh) })
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
		system := systemAnswer(ips, err, time.Since(started))

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

		dnsCheck(ctx, host, system, sh)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// dnsCheck compares the system answer with the DoH resolvers and records the
// result.
func dnsCheck(ctx context.Context, host string, system dnsAnswer, sh *shared) {
	rec := sh.dns.check(ctx, host, system)
	if ctx.Err() != nil {
		return
	}

	_ = sh.store.write(rec.TS, rec)

	for _, ev := range dnsEvents(rec) {
		_ = sh.store.writeEvent(ev)
	}

	sh.p.line(rec.TS, host, "nc-dns", rec.ok(), time.Duration(system.MS*float64(time.Millisecond)), rec.detail())
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
