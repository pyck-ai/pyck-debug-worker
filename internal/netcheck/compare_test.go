package netcheck

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCompareLoop(t *testing.T) {
	ln, target := listen(t, nil)
	target.Host = "alidns"

	closed, refused := listen(t, nil)
	refused.Host = "cloudflare"
	_ = closed.Close()

	a := newAgg()
	a.register(testTarget)
	a.registerModes(target, []string{modeCompare})
	a.registerModes(refused, []string{modeCompare})

	// One connect each: the next is shortInterval away.
	for _, ct := range []Target{target, refused} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		compareLoop(ctx, ct, a)
		cancel()
	}

	_ = ln.Close()

	got := a.flush(testMinute)
	if len(got) != 5 {
		t.Fatalf("flush returned %d aggregates, want 3 for the host and 1 per comparison target", len(got))
	}

	ok, fail := got[3], got[4]

	if ok.Mode != modeCompare || ok.Host != "alidns" || ok.Samples != 1 || ok.Connect == nil || ok.TLS != nil || !ok.ok() {
		t.Errorf("reachable = %+v, want one connect, no TLS, ok", ok)
	}

	if ok.duration() != time.Duration(ok.Connect.P50*float64(time.Millisecond)) {
		t.Errorf("duration = %s, want the connect p50", ok.duration())
	}

	if fail.Samples != 1 || fail.Failures[classRefused] != 1 || fail.ok() {
		t.Errorf("refused = %+v, want one refused sample, FAIL", fail)
	}

	if !strings.HasPrefix(ok.label(), "alidns/127.0.0.1") || strings.Contains(ok.detail(), "drops") {
		t.Errorf("label %q detail %q", ok.label(), ok.detail())
	}
}

func TestCompareTargets(t *testing.T) {
	want := map[string]netip.Addr{
		"alidns":     netip.MustParseAddr("223.5.5.5"),
		"cloudflare": netip.MustParseAddr("1.1.1.1"),
	}

	for _, ct := range compareTargets {
		if want[ct.Host] != ct.IP || ct.Port != 443 {
			t.Errorf("comparison target %+v", ct)
		}
	}
}
