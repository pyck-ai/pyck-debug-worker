package netcheck

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCarrierOf(t *testing.T) {
	tests := map[string]string{
		"59.43.10.1":     "CN2",
		"202.97.33.5":    "ChinaNet",
		"219.158.3.9":    "Unicom-AS4837",
		"223.120.2.1":    "ChinaMobile",
		"223.121.255.1":  "ChinaMobile",
		"192.0.2.1":      "",
		"198.51.100.200": "",
	}

	for ip, want := range tests {
		if got := carrierOf(netip.MustParseAddr(ip)); got != want {
			t.Errorf("carrierOf(%s) = %q, want %q", ip, got, want)
		}
	}
}

// hops builds a trace from IPs, "" for a silent TTL.
func hops(ips ...string) []traceHop {
	out := make([]traceHop, 0, len(ips))
	for i, ip := range ips {
		out = append(out, traceHop{TTL: i + 1, IP: ip})
	}

	return out
}

func TestRouteChanged(t *testing.T) {
	base := traceRecord{Hops: hops("192.0.2.1", "198.51.100.1", "203.0.113.9"), Reached: true}

	tests := []struct {
		name string
		cur  traceRecord
		want bool
	}{
		{name: "same", cur: base, want: false},
		{name: "silent hop matches anything", cur: traceRecord{Hops: hops("192.0.2.1", "", "203.0.113.9"), Reached: true}},
		{name: "different hop", cur: traceRecord{Hops: hops("192.0.2.1", "198.51.100.2", "203.0.113.9"), Reached: true}, want: true},
		{name: "longer path to the destination", cur: traceRecord{Hops: hops("192.0.2.1", "198.51.100.1", "198.51.100.5", "203.0.113.9"), Reached: true}, want: true},
		{name: "cut short without reaching", cur: traceRecord{Hops: hops("192.0.2.1", "198.51.100.1")}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeChanged(base, tc.cur); got != tc.want {
				t.Errorf("routeChanged = %v, want %v", got, tc.want)
			}
		})
	}

	if got := path(hops("192.0.2.1", "")); !slices.Equal(got, []string{"192.0.2.1", "*"}) {
		t.Errorf("path = %v", got)
	}
}

func TestTraceDetail(t *testing.T) {
	rec := traceRecord{
		Reason: reasonJump, Reached: true, PMTU: 1500, Changed: true,
		Hops: []traceHop{{TTL: 1, IP: "192.0.2.1"}, {TTL: 2, IP: "59.43.1.1", Carrier: "CN2"}, {TTL: 3, IP: "59.43.1.2", Carrier: "CN2"}},
	}

	want := "latency-jump  hops=3  reached  pmtu=1500  carriers=CN2  route-changed"
	if got := rec.detail(); got != want {
		t.Errorf("detail\n got %q\nwant %q", got, want)
	}
}

func TestJumpedRTT(t *testing.T) {
	tests := []struct {
		prev, cur float64
		want      bool
	}{
		{prev: 100, cur: 129, want: false},
		{prev: 100, cur: 131, want: true},
		{prev: 2, cur: 9, want: false}, // +350% but only 7ms
		{prev: 20, cur: 31, want: true},
		{prev: 100, cur: 60, want: false},
	}

	for _, tc := range tests {
		if got := jumpedRTT(tc.prev, tc.cur); got != tc.want {
			t.Errorf("jumpedRTT(%v, %v) = %v, want %v", tc.prev, tc.cur, got, tc.want)
		}
	}
}

func TestJumpsObserve(t *testing.T) {
	j := newJumps()
	ch := j.watch(testTarget)

	long := func(p50 float64) []aggregate {
		rec := aggregate{Mode: modeLong, target: testTarget, RTT: &stats{P50: p50}}
		if p50 == 0 {
			rec.RTT = nil
		}

		return []aggregate{{Mode: modeShort, target: testTarget, Connect: &stats{P50: 999}}, rec}
	}

	fired := func() bool {
		select {
		case <-ch:
			return true
		case <-time.After(10 * time.Millisecond):
			return false
		}
	}

	j.observe(long(100))

	if fired() {
		t.Error("first minute has nothing to compare with")
	}

	j.observe(long(200))

	if !fired() {
		t.Error("100 → 200ms must trigger")
	}

	j.observe(long(210))
	j.observe(long(0)) // no PING answered: forgets the baseline
	j.observe(long(400))

	if fired() {
		t.Error("a jump across a minute without data must not trigger")
	}

	j.unwatch(testTarget)
	j.observe(long(100))
	j.observe(long(900))

	if fired() {
		t.Error("an unwatched target must not trigger")
	}
}

func TestTraceRecordShape(t *testing.T) {
	rec := traceRecord{Type: "trace", Reason: reasonHourly, Hops: []traceHop{}, Error: "boom"}
	if !strings.Contains(rec.detail(), "not-reached") || !strings.HasSuffix(rec.detail(), "boom") {
		t.Errorf("detail %q", rec.detail())
	}
}
