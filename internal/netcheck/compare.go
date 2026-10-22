package netcheck

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// compareTargets are measured once, not per host: a TCP connect only, no TLS
// and no data. AliDNS is inside China, Cloudflare outside, so together they
// separate "the local network is bad" from "the border crossing is bad".
var compareTargets = []Target{
	{Host: "alidns", IP: netip.MustParseAddr("223.5.5.5"), Port: port},
	{Host: "cloudflare", IP: netip.MustParseAddr("1.1.1.1"), Port: port},
}

// compareLoop connects to t every shortInterval until ctx ends.
func compareLoop(ctx context.Context, t Target, agg *agg) {
	ticker := time.NewTicker(shortInterval)
	defer ticker.Stop()

	for {
		took, err := connectOnce(ctx, t)

		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			agg.fail(t, modeCompare, classify(err))
		default:
			agg.connect(t, took, synRetrans(took))
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// connectOnce opens a TCP connection to t and closes it at once.
func connectOnce(ctx context.Context, t Target) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	var dialer net.Dialer

	started := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", t.addr())
	took := time.Since(started)

	if err != nil {
		return took, err
	}

	_ = conn.Close()

	return took, nil
}
