package netcheck

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Route trace timing.
const (
	// traceInterval is how often each target is traced.
	traceInterval = time.Hour
	// traceMinGap rate-limits latency-jump traces per target.
	traceMinGap = 10 * time.Minute
	// traceTimeout bounds one trace.
	traceTimeout = 3 * time.Minute
)

// A latency jump is a long-connection p50 RTT more than jumpRatio times and
// at least jumpMinMS above the previous minute's. The absolute floor keeps a
// 2ms LAN path from triggering on 1ms of noise.
const (
	jumpRatio = 1.3
	jumpMinMS = 10
)

// Why a trace ran.
const (
	reasonStartup = "startup"
	reasonHourly  = "hourly"
	reasonJump    = "latency-jump"
)

// carriers tags hop IPs with the carrier backbone they belong to.
var carriers = []struct {
	prefix netip.Prefix
	name   string
}{
	{netip.MustParsePrefix("59.43.0.0/16"), "CN2"},
	{netip.MustParsePrefix("202.97.0.0/16"), "ChinaNet"},
	{netip.MustParsePrefix("219.158.0.0/16"), "Unicom-AS4837"},
	{netip.MustParsePrefix("223.120.0.0/15"), "ChinaMobile"},
}

// carrierOf is ip's carrier tag, or "".
func carrierOf(ip netip.Addr) string {
	for _, c := range carriers {
		if c.prefix.Contains(ip) {
			return c.name
		}
	}

	return ""
}

// traceHop is one TTL of a trace. IP is empty when nothing answered.
type traceHop struct {
	TTL     int     `json:"ttl"`
	IP      string  `json:"ip,omitempty"`
	RTTMS   float64 `json:"rtt_ms,omitempty"`
	Carrier string  `json:"carrier,omitempty"`
}

// traceResult is what a trace found.
type traceResult struct {
	hops []traceHop
	// reached is set when the destination itself answered.
	reached bool
	// pmtu is the path MTU the probes ended with.
	pmtu int
}

// traceRecord is one route trace.
type traceRecord struct {
	Type       string     `json:"type"`
	TS         time.Time  `json:"ts"`
	Host       string     `json:"host"`
	IP         string     `json:"ip"`
	Reason     string     `json:"reason"`
	Hops       []traceHop `json:"hops"`
	Reached    bool       `json:"reached"`
	PMTU       int        `json:"pmtu,omitempty"`
	DurationMS float64    `json:"duration_ms"`
	Changed    bool       `json:"route_changed,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// detail is the stdout detail column.
func (r traceRecord) detail() string {
	parts := []string{r.Reason, fmt.Sprintf("hops=%d", len(r.Hops))}

	if r.Reached {
		parts = append(parts, "reached")
	} else {
		parts = append(parts, "not-reached")
	}

	if r.PMTU > 0 {
		parts = append(parts, fmt.Sprintf("pmtu=%d", r.PMTU))
	}

	var tags []string

	for _, h := range r.Hops {
		if h.Carrier != "" && !slices.Contains(tags, h.Carrier) {
			tags = append(tags, h.Carrier)
		}
	}

	if len(tags) > 0 {
		parts = append(parts, "carriers="+strings.Join(tags, ","))
	}

	if r.Changed {
		parts = append(parts, "route-changed")
	}

	if r.Error != "" {
		parts = append(parts, r.Error)
	}

	return strings.Join(parts, "  ")
}

// path is the hop IPs in TTL order, "*" for no answer.
func path(hops []traceHop) []string {
	out := make([]string, 0, len(hops))

	for _, h := range hops {
		ip := h.IP
		if ip == "" {
			ip = "*"
		}

		out = append(out, ip)
	}

	return out
}

// routeChanged compares two traces. A TTL that did not answer in either one
// matches anything, so a lost probe is not a route change; a TTL answered by
// different IPs is, as is a different hop count when both reached the
// destination.
func routeChanged(prev, cur traceRecord) bool {
	for i := range min(len(prev.Hops), len(cur.Hops)) {
		a, b := prev.Hops[i].IP, cur.Hops[i].IP
		if a != "" && b != "" && a != b {
			return true
		}
	}

	return prev.Reached && cur.Reached && len(prev.Hops) != len(cur.Hops)
}

// traceLoop traces the route to t at startup, every traceInterval and, at
// most every traceMinGap, when its long-connection RTT jumps. A route
// different from the previous trace's is a route-changed event. Only Linux
// can trace unprivileged; elsewhere it does nothing.
func traceLoop(ctx context.Context, t Target, sh *shared) {
	if !traceSupported {
		return
	}

	jumped := sh.jumps.watch(t)
	defer sh.jumps.unwatch(t)

	ticker := time.NewTicker(traceInterval)
	defer ticker.Stop()

	var (
		prev     traceRecord
		lastRun  time.Time
		reason   = reasonStartup
		havePrev bool
	)

	for {
		rec := runTrace(ctx, t, reason)
		lastRun = time.Now()

		if ctx.Err() != nil {
			return
		}

		if rec.Error == "" {
			if havePrev && routeChanged(prev, rec) {
				rec.Changed = true

				ev := newEvent(eventRouteChanged, t)
				ev.Path, ev.PrevPath = path(rec.Hops), path(prev.Hops)
				_ = sh.store.writeEvent(ev)
			}

			prev, havePrev = rec, true
		}

		_ = sh.store.write(rec.TS, rec)
		sh.p.line(rec.TS, t.Label(), "nc-trace", rec.Error == "",
			time.Duration(rec.DurationMS*float64(time.Millisecond)), rec.detail())

		for wait := true; wait; {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reason, wait = reasonHourly, false
			case <-jumped:
				if time.Since(lastRun) >= traceMinGap {
					reason, wait = reasonJump, false
				}
			}
		}
	}
}

// runTrace traces t once.
func runTrace(ctx context.Context, t Target, reason string) traceRecord {
	ctx, cancel := context.WithTimeout(ctx, traceTimeout)
	defer cancel()

	rec := traceRecord{Type: "trace", TS: time.Now().UTC(), Host: t.Host, IP: t.IP.String(), Reason: reason}
	started := time.Now()

	res, err := traceRoute(ctx, t.IP)

	rec.DurationMS = round(ms(time.Since(started)))
	rec.Hops, rec.Reached, rec.PMTU = res.hops, res.reached, res.pmtu

	if rec.Hops == nil {
		rec.Hops = []traceHop{}
	}

	if err != nil {
		rec.Error = err.Error()
	}

	return rec
}

// jumps watches each target's long-connection p50 RTT, minute over minute,
// and wakes its trace loop on a jump.
type jumps struct {
	mu       sync.Mutex
	prev     map[Target]float64
	triggers map[Target]chan struct{}
}

func newJumps() *jumps {
	return &jumps{prev: map[Target]float64{}, triggers: map[Target]chan struct{}{}}
}

// watch registers t's trace loop.
func (j *jumps) watch(t Target) <-chan struct{} {
	j.mu.Lock()
	defer j.mu.Unlock()

	ch := make(chan struct{}, 1)
	j.triggers[t] = ch

	return ch
}

// unwatch forgets t.
func (j *jumps) unwatch(t Target) {
	j.mu.Lock()
	defer j.mu.Unlock()

	delete(j.triggers, t)
	delete(j.prev, t)
}

// observe checks a minute's aggregates for latency jumps.
func (j *jumps) observe(recs []aggregate) {
	j.mu.Lock()
	defer j.mu.Unlock()

	for _, rec := range recs {
		ch, watched := j.triggers[rec.target]
		if rec.Mode != modeLong || !watched {
			continue
		}

		if rec.RTT == nil {
			delete(j.prev, rec.target)

			continue
		}

		if prev, ok := j.prev[rec.target]; ok && jumpedRTT(prev, rec.RTT.P50) {
			select {
			case ch <- struct{}{}:
			default:
			}
		}

		j.prev[rec.target] = rec.RTT.P50
	}
}

// jumpedRTT reports whether cur is a latency jump over prev.
func jumpedRTT(prev, cur float64) bool {
	return cur > prev*jumpRatio && cur-prev >= jumpMinMS
}
