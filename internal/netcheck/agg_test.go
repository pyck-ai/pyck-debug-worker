package netcheck

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	testMinute = time.Date(2026, 10, 19, 12, 30, 0, 0, time.UTC)
	testTarget = Target{Host: "dev.pyck.cloud", IP: netip.MustParseAddr("192.0.2.10"), Port: port}
)

func TestSummarise(t *testing.T) {
	tests := []struct {
		name    string
		samples []float64
		want    *stats
	}{
		{name: "empty", samples: nil, want: nil},
		{
			name:    "single sample has no jitter",
			samples: []float64{12.5},
			want:    &stats{Min: 12.5, P50: 12.5, P95: 12.5, P99: 12.5, Max: 12.5},
		},
		{
			name:    "nearest rank and mean consecutive difference",
			samples: []float64{40, 10, 30, 20},
			// sorted 10 20 30 40: p50 rank 2, p95 and p99 rank 4.
			// jitter |10-40|+|30-10|+|20-30| = 60 over 3.
			want: &stats{Min: 10, P50: 20, P95: 40, P99: 40, Max: 40, Jitter: 20},
		},
		{
			name:    "hundred samples",
			samples: seq(1, 100),
			want:    &stats{Min: 1, P50: 50, P95: 95, P99: 99, Max: 100, Jitter: 1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarise(tc.samples); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("summarise(%v) = %+v, want %+v", tc.samples, got, tc.want)
			}
		})
	}
}

// seq returns from..to as floats.
func seq(from, to int) []float64 {
	out := make([]float64, 0, to-from+1)
	for i := from; i <= to; i++ {
		out = append(out, float64(i))
	}

	return out
}

func TestSynRetrans(t *testing.T) {
	tests := []struct {
		connect time.Duration
		want    int
	}{
		{connect: 30 * time.Millisecond, want: 0},
		{connect: 999 * time.Millisecond, want: 0},
		{connect: 1030 * time.Millisecond, want: 1},
		{connect: 3030 * time.Millisecond, want: 2},
	}

	for _, tc := range tests {
		if got := synRetrans(tc.connect); got != tc.want {
			t.Errorf("synRetrans(%s) = %d, want %d", tc.connect, got, tc.want)
		}
	}
}

func TestAggFlush(t *testing.T) {
	a := newAgg()
	a.register(testTarget)

	a.short(testTarget, 10*time.Millisecond, 20*time.Millisecond, 0)
	a.short(testTarget, 1100*time.Millisecond, 30*time.Millisecond, 1)
	a.fail(testTarget, modeShort, classReset)
	a.ping(testTarget, modeLong, 5*time.Millisecond)
	a.ping(testTarget, modeLong, 7*time.Millisecond)
	a.lostPing(testTarget, modeLong)
	a.serverClosed(testTarget, modeLong)
	a.tcpInfo(testTarget, tcpInfo{RTT: 6 * time.Millisecond, RTTVar: time.Millisecond}, 2)
	a.tcpInfo(testTarget, tcpInfo{RTT: 8 * time.Millisecond, RTTVar: 2 * time.Millisecond}, 1)

	got := a.flush(testMinute)
	if len(got) != 3 {
		t.Fatalf("flush returned %d aggregates, want 3 (short, long, idle)", len(got))
	}

	short, long := got[0], got[1]

	if short.Mode != modeShort || short.Samples != 3 || short.Losses != 1 ||
		short.Failures[classReset] != 1 || short.Connect.Max != 1100 || short.TLS.Min != 20 {
		t.Errorf("short aggregate wrong: %+v", short)
	}

	if short.ok() {
		t.Error("short minute with a loss and a failure must be FAIL")
	}

	if long.Mode != modeLong || long.Samples != 3 || long.Losses != 1 || long.RTT.P50 != 5 ||
		long.ServerClosed != 1 || long.Drops != 0 ||
		*long.TCP != (tcpStats{RTT: 8, RTTVar: 2, Retrans: 3}) {
		t.Errorf("long aggregate wrong: %+v tcp %+v", long, long.TCP)
	}

	if !long.TS.Equal(testMinute) || long.Host != testTarget.Host || long.IP != "192.0.2.10" {
		t.Errorf("long aggregate identity wrong: %+v", long)
	}

	// The next minute starts empty and clean.
	next := a.flush(testMinute.Add(time.Minute))
	if len(next) != 3 || next[0].Samples != 0 || next[1].Samples != 0 || !next[0].ok() || !next[1].ok() {
		t.Errorf("second flush not reset: %+v", next)
	}
}

func TestAggOK(t *testing.T) {
	tests := []struct {
		name string
		in   aggregate
		want bool
	}{
		{name: "clean", in: aggregate{Samples: 60}, want: true},
		{name: "server close is not a failure", in: aggregate{Samples: 60, ServerClosed: 1}, want: true},
		{name: "loss", in: aggregate{Samples: 60, Losses: 1}, want: false},
		{name: "failure", in: aggregate{Failures: map[string]int{classTimeout: 1}}, want: false},
		{name: "drop", in: aggregate{Samples: 60, Drops: 1}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.ok(); got != tc.want {
				t.Errorf("ok() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAggUnregisterKeepsLastMinute(t *testing.T) {
	a := newAgg()
	a.register(testTarget)
	a.ping(testTarget, modeLong, time.Millisecond)
	a.unregister(testTarget)

	got := a.flush(testMinute)
	if len(got) != 3 || got[1].Samples != 1 {
		t.Fatalf("last minute of a removed target lost: %+v", got)
	}

	if again := a.flush(testMinute.Add(time.Minute)); len(again) != 0 {
		t.Errorf("removed target still emitted: %+v", again)
	}

	// Samples for an unregistered target are ignored.
	a.ping(testTarget, modeLong, time.Millisecond)

	if again := a.flush(testMinute.Add(2 * time.Minute)); len(again) != 0 {
		t.Errorf("unregistered target collected samples: %+v", again)
	}
}

func TestAggregateLine(t *testing.T) {
	a := newAgg()
	a.register(testTarget)
	a.ping(testTarget, modeLong, 12*time.Millisecond)
	a.drop(testTarget, modeLong)
	a.fail(testTarget, modeLong, classRefused)

	long := a.flush(testMinute)[1]

	if long.label() != "dev.pyck.cloud/192.0.2.10" {
		t.Errorf("label = %q", long.label())
	}

	if long.duration() != 12*time.Millisecond {
		t.Errorf("duration = %s, want the p50 RTT", long.duration())
	}

	want := "n=1 lost=0 drops=1  fail=refused:1  rtt min/p50/p95/p99/max 12.0/12.0/12.0/12.0/12.0ms jitter 0.0ms"
	if got := long.detail(); got != want {
		t.Errorf("detail\n got %q\nwant %q", got, want)
	}

	bare := Target{Host: "192.0.2.10", IP: testTarget.IP}
	if !strings.EqualFold(bare.Label(), "192.0.2.10") || bare.serverName() != "" {
		t.Errorf("bare IP target: label %q sni %q", bare.Label(), bare.serverName())
	}
}
