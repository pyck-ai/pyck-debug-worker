package netcheck

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Measurement modes.
const (
	modeShort = "short"
	modeLong  = "long"
	modeIdle  = "idle"
)

// modes is the per-target emission order.
var modes = []string{modeShort, modeLong, modeIdle}

// stats summarises one minute of latency samples, in milliseconds.
type stats struct {
	Min    float64 `json:"min_ms"`
	P50    float64 `json:"p50_ms"`
	P95    float64 `json:"p95_ms"`
	P99    float64 `json:"p99_ms"`
	Max    float64 `json:"max_ms"`
	Jitter float64 `json:"jitter_ms"`
}

// tcpStats is the kernel's view of the long connection (Linux only): the last
// smoothed RTT and its variance, and the retransmits counted this minute.
type tcpStats struct {
	RTT     float64 `json:"rtt_ms"`
	RTTVar  float64 `json:"rttvar_ms"`
	Retrans uint32  `json:"retrans"`
}

// certInfo is a certificate that failed verification.
type certInfo struct {
	Fingerprint string `json:"fingerprint"`
	Issuer      string `json:"issuer"`
	Error       string `json:"error"`
}

// idleStats is the idle connection at the end of the minute.
type idleStats struct {
	// SurvivedS is the longest gap the current connection survived.
	SurvivedS float64 `json:"survived_s"`
	// Died is the minute's last idle connection death, if any.
	Died *idleDeath `json:"died,omitempty"`
}

// idleDeath is how an idle connection ended.
type idleDeath struct {
	// GapS is the gap after which the PING failed; 0 is the first PING
	// right after connecting.
	GapS float64 `json:"gap_s"`
	// SurvivedS is the longest gap the connection had survived before.
	SurvivedS float64 `json:"survived_s"`
	// How is timeout, reset, other or server-closed.
	How string `json:"how"`
}

// aggregate is one minute of one mode for one target.
//
// samples are connection attempts (short) or answered plus unanswered pings
// (long). losses are SYN retransmits inferred from connect time (short) or
// unanswered pings (long).
type aggregate struct {
	Type         string         `json:"type"`
	TS           time.Time      `json:"ts"`
	Host         string         `json:"host"`
	IP           string         `json:"ip"`
	Mode         string         `json:"mode"`
	Samples      int            `json:"samples"`
	Losses       int            `json:"losses"`
	Connect      *stats         `json:"connect,omitempty"`
	TLS          *stats         `json:"tls,omitempty"`
	RTT          *stats         `json:"rtt,omitempty"`
	Failures     map[string]int `json:"failures,omitempty"`
	Drops        int            `json:"drops"`
	ServerClosed int            `json:"server_closed,omitempty"`
	TCP          *tcpStats      `json:"tcp,omitempty"`
	// Cert is the last intercepted certificate seen this minute; the count
	// is failures["intercepted"].
	Cert *certInfo `json:"intercepted_cert,omitempty"`
	// Idle is set for the idle mode.
	Idle *idleStats `json:"idle,omitempty"`

	target Target
}

// failures sums the failure counts.
func (a aggregate) failures() int {
	n := 0
	for _, c := range a.Failures {
		n += c
	}

	return n
}

// ok is false on any loss, failure or drop. A server-initiated close is not a
// drop.
func (a aggregate) ok() bool {
	return a.Losses == 0 && a.failures() == 0 && a.Drops == 0
}

// label is the stdout target column.
func (a aggregate) label() string {
	return a.target.Label()
}

// duration is the stdout duration column: the median latency of the minute.
func (a aggregate) duration() time.Duration {
	s := a.RTT
	if a.Mode == modeShort {
		s = a.Connect
	}

	if s == nil {
		return 0
	}

	return time.Duration(s.P50 * float64(time.Millisecond))
}

// detail is the stdout detail column.
func (a aggregate) detail() string {
	parts := []string{fmt.Sprintf("n=%d lost=%d", a.Samples, a.Losses)}

	if a.Mode == modeLong || a.Mode == modeIdle {
		parts[0] += fmt.Sprintf(" drops=%d", a.Drops)

		if a.ServerClosed > 0 {
			parts[0] += fmt.Sprintf(" server-closed=%d", a.ServerClosed)
		}
	}

	if len(a.Failures) > 0 {
		classes := make([]string, 0, len(a.Failures))
		for class, n := range a.Failures {
			classes = append(classes, fmt.Sprintf("%s:%d", class, n))
		}

		sort.Strings(classes)
		parts = append(parts, "fail="+strings.Join(classes, ","))
	}

	for _, s := range []struct {
		name string
		s    *stats
	}{{"connect", a.Connect}, {"tls", a.TLS}, {"rtt", a.RTT}} {
		if s.s != nil {
			parts = append(parts, fmt.Sprintf("%s min/p50/p95/p99/max %.1f/%.1f/%.1f/%.1f/%.1fms jitter %.1fms",
				s.name, s.s.Min, s.s.P50, s.s.P95, s.s.P99, s.s.Max, s.s.Jitter))
		}
	}

	if a.Idle != nil {
		parts = append(parts, fmt.Sprintf("survived %ss", formatSeconds(a.Idle.SurvivedS)))

		if d := a.Idle.Died; d != nil {
			parts = append(parts, fmt.Sprintf("died after %ss gap: %s (had survived %ss)",
				formatSeconds(d.GapS), d.How, formatSeconds(d.SurvivedS)))
		}
	}

	if a.Cert != nil {
		parts = append(parts, fmt.Sprintf("intercepted issuer %q sha256 %.16s…", a.Cert.Issuer, a.Cert.Fingerprint))
	}

	if a.TCP != nil {
		parts = append(parts, fmt.Sprintf("tcp rtt %.1fms rttvar %.1fms retrans %d",
			a.TCP.RTT, a.TCP.RTTVar, a.TCP.Retrans))
	}

	return strings.Join(parts, "  ")
}

// formatSeconds renders whole seconds without a fraction.
func formatSeconds(s float64) string {
	return strconv.FormatFloat(s, 'f', -1, 64)
}

// bucket accumulates one minute of one mode for one target.
type bucket struct {
	samples      int
	losses       int
	connect      []float64
	tls          []float64
	rtt          []float64
	failures     map[string]int
	drops        int
	serverClosed int
	tcp          *tcpStats
	cert         *certInfo
	died         *idleDeath
}

// bucketKey identifies a bucket.
type bucketKey struct {
	target Target
	mode   string
}

// agg holds the current minute's buckets for every registered target.
type agg struct {
	mu      sync.Mutex
	targets []Target
	removed map[Target]bool
	buckets map[bucketKey]*bucket
	// lastFP is the last intercepted fingerprint per target, across minutes
	// and modes, so only a first occurrence or a change becomes an event.
	lastFP map[Target]string
	// survived is the longest gap each target's current idle connection
	// survived, across minutes.
	survived map[Target]float64
}

func newAgg() *agg {
	return &agg{
		removed:  map[Target]bool{},
		buckets:  map[bucketKey]*bucket{},
		lastFP:   map[Target]string{},
		survived: map[Target]float64{},
	}
}

// register starts collecting for t.
func (a *agg) register(t Target) {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.removed, t)

	if !slices.Contains(a.targets, t) {
		a.targets = append(a.targets, t)
	}

	for _, mode := range modes {
		if _, ok := a.buckets[bucketKey{t, mode}]; !ok {
			a.buckets[bucketKey{t, mode}] = &bucket{}
		}
	}
}

// unregister stops collecting for t after its current minute is flushed, so
// its last partial minute is kept.
func (a *agg) unregister(t Target) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.removed[t] = true
}

// with runs fn on the bucket for (t, mode), if t is registered.
func (a *agg) with(t Target, mode string, fn func(b *bucket)) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if b, ok := a.buckets[bucketKey{t, mode}]; ok {
		fn(b)
	}
}

// fail counts a failed connect or handshake.
func (a *agg) fail(t Target, mode, class string) {
	a.with(t, mode, func(b *bucket) {
		if b.failures == nil {
			b.failures = map[string]int{}
		}

		b.failures[class]++

		if mode == modeShort {
			b.samples++
		}
	})
}

// intercepted counts an intercepted handshake as a failure, keeps the
// certificate for the minute, and reports whether it is the target's first
// interception or a new fingerprint.
func (a *agg) intercepted(t Target, mode string, info interception) bool {
	a.with(t, mode, func(b *bucket) {
		// No sample is counted here: a short handshake already is one via
		// short(), a failed long dial never is.
		if b.failures == nil {
			b.failures = map[string]int{}
		}

		b.failures[classIntercepted]++
		b.cert = &certInfo{Fingerprint: info.Fingerprint, Issuer: info.Issuer, Error: info.Err}
	})

	a.mu.Lock()
	defer a.mu.Unlock()

	if last, seen := a.lastFP[t]; seen && last == info.Fingerprint {
		return false
	}

	a.lastFP[t] = info.Fingerprint

	return true
}

// short records one completed short connection.
func (a *agg) short(t Target, connect, handshake time.Duration, synRetrans int) {
	a.with(t, modeShort, func(b *bucket) {
		b.samples++
		b.losses += synRetrans
		b.connect = append(b.connect, ms(connect))
		b.tls = append(b.tls, ms(handshake))
	})
}

// ping records one answered PING on the long or idle connection.
func (a *agg) ping(t Target, mode string, rtt time.Duration) {
	a.with(t, mode, func(b *bucket) {
		b.samples++
		b.rtt = append(b.rtt, ms(rtt))
	})
}

// lostPing records one unanswered PING on the long or idle connection.
func (a *agg) lostPing(t Target, mode string) {
	a.with(t, mode, func(b *bucket) {
		b.samples++
		b.losses++
	})
}

// drop records the long or idle connection dying.
func (a *agg) drop(t Target, mode string) {
	a.with(t, mode, func(b *bucket) { b.drops++ })
}

// serverClosed records the server closing the long or idle connection on
// purpose.
func (a *agg) serverClosed(t Target, mode string) {
	a.with(t, mode, func(b *bucket) { b.serverClosed++ })
}

// idleSurvived sets the longest gap t's current idle connection survived; 0
// starts a new connection.
func (a *agg) idleSurvived(t Target, gap time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.buckets[bucketKey{t, modeIdle}]; ok {
		a.survived[t] = gap.Seconds()
	}
}

// idleDied records how t's idle connection ended.
func (a *agg) idleDied(t Target, d idleDeath) {
	a.with(t, modeIdle, func(b *bucket) { b.died = &d })
}

// tcpInfo records a TCP_INFO reading and the retransmits since the last one.
func (a *agg) tcpInfo(t Target, info tcpInfo, retrans uint32) {
	a.with(t, modeLong, func(b *bucket) {
		if b.tcp == nil {
			b.tcp = &tcpStats{}
		}

		b.tcp.RTT = ms(info.RTT)
		b.tcp.RTTVar = ms(info.RTTVar)
		b.tcp.Retrans += retrans
	})
}

// flush returns the aggregates for minute, in registration order, and starts
// a fresh minute. Targets unregistered during the minute are emitted one last
// time and then forgotten.
func (a *agg) flush(minute time.Time) []aggregate {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]aggregate, 0, len(a.targets)*len(modes))
	kept := a.targets[:0]

	for _, t := range a.targets {
		for _, mode := range modes {
			key := bucketKey{t, mode}
			rec := a.buckets[key].aggregate(minute, t, mode)

			if mode == modeIdle {
				rec.Idle = &idleStats{SurvivedS: a.survived[t], Died: a.buckets[key].died}
			}

			out = append(out, rec)
			a.buckets[key] = &bucket{}
		}

		if a.removed[t] {
			delete(a.removed, t)

			for _, mode := range modes {
				delete(a.buckets, bucketKey{t, mode})
			}

			delete(a.lastFP, t)
			delete(a.survived, t)

			continue
		}

		kept = append(kept, t)
	}

	a.targets = kept

	return out
}

// aggregate summarises the bucket.
func (b *bucket) aggregate(minute time.Time, t Target, mode string) aggregate {
	return aggregate{
		Type:         "agg",
		TS:           minute.UTC(),
		Host:         t.Host,
		IP:           t.IP.String(),
		Mode:         mode,
		Samples:      b.samples,
		Losses:       b.losses,
		Connect:      summarise(b.connect),
		TLS:          summarise(b.tls),
		RTT:          summarise(b.rtt),
		Failures:     b.failures,
		Drops:        b.drops,
		ServerClosed: b.serverClosed,
		TCP:          b.tcp,
		Cert:         b.cert,
		target:       t,
	}
}

// summarise computes min/percentiles/max and jitter. Percentiles are
// nearest-rank; jitter is the mean absolute difference between consecutive
// samples in arrival order. It returns nil for no samples.
func summarise(samples []float64) *stats {
	if len(samples) == 0 {
		return nil
	}

	jitter := 0.0
	for i := 1; i < len(samples); i++ {
		jitter += math.Abs(samples[i] - samples[i-1])
	}

	if len(samples) > 1 {
		jitter /= float64(len(samples) - 1)
	}

	sorted := slices.Clone(samples)
	slices.Sort(sorted)

	return &stats{
		Min:    round(sorted[0]),
		P50:    round(percentile(sorted, 50)),
		P95:    round(percentile(sorted, 95)),
		P99:    round(percentile(sorted, 99)),
		Max:    round(sorted[len(sorted)-1]),
		Jitter: round(jitter),
	}
}

// percentile is the nearest-rank percentile of sorted, non-empty samples.
func percentile(sorted []float64, p int) float64 {
	rank := int(math.Ceil(float64(p) / 100 * float64(len(sorted))))

	return sorted[max(rank, 1)-1]
}

// ms converts a duration to milliseconds.
func ms(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// round keeps microsecond precision.
func round(v float64) float64 {
	return math.Round(v*1000) / 1000
}
