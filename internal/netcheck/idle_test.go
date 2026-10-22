package netcheck

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// fastIdle shortens the idle gaps and the PING deadline for the test.
func fastIdle(t *testing.T) {
	t.Helper()

	oldGaps, oldDead := idleGaps, deadAfter
	idleGaps, deadAfter = []time.Duration{20 * time.Millisecond, 40 * time.Millisecond}, 200*time.Millisecond

	t.Cleanup(func() { idleGaps, deadAfter = oldGaps, oldDead })
}

// runIdle dials target and runs one idle session until it ends or timeout
// passes.
func runIdle(t *testing.T, target Target, timeout time.Duration) (aggregate, event, bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialH2(ctx, target, net.Dialer{KeepAlive: -1})
	if err != nil {
		t.Fatalf("dialH2: %v", err)
	}

	a := newAgg()
	a.register(target)

	ev, ended := idleSession(ctx, target, conn, a)

	return a.flush(testMinute)[2], ev, ended
}

func TestIdleSession(t *testing.T) {
	fastIdle(t)

	cert, roots := testCert(t)

	t.Run("survives every gap", func(t *testing.T) {
		target := pingServer(t, cert, roots, true, -1, nil)

		idle, _, ended := runIdle(t, target, 300*time.Millisecond)

		if ended {
			t.Fatal("session ended although every PING was answered")
		}

		// 0, 20ms, 40ms, then 40ms repeated: the longest survived gap is
		// the last one in the list.
		if idle.Mode != modeIdle || idle.Idle == nil || idle.Idle.SurvivedS != 0.04 || idle.Idle.Died != nil {
			t.Errorf("aggregate = %+v idle %+v, want survived 0.04s and no death", idle, idle.Idle)
		}

		if idle.Samples < 3 || idle.RTT == nil || !idle.ok() {
			t.Errorf("aggregate = %+v, want >=3 answered PINGs, ok", idle)
		}
	})

	t.Run("reset after a gap is a drop", func(t *testing.T) {
		// PINGs 1 (no gap) and 2 (20ms) are answered, 3 (40ms) is reset.
		target := pingServer(t, cert, roots, true, 2, func(conn *net.TCPConn, _ *http2.Framer) { reset(conn) })

		idle, ev, ended := runIdle(t, target, 5*time.Second)
		if !ended {
			t.Fatal("session did not end")
		}

		if ev.Event != eventDrop || ev.Mode != modeIdle || ev.Class != classReset ||
			ev.GapS != 0.04 || ev.SurvivedS != 0.02 || ev.LifetimeS <= 0 {
			t.Errorf("event = %+v, want a reset drop after the 40ms gap having survived 20ms", ev)
		}

		want := idleDeath{GapS: 0.04, SurvivedS: 0.02, How: classReset}
		if idle.Idle == nil || idle.Idle.Died == nil || *idle.Idle.Died != want || idle.Idle.SurvivedS != 0 {
			t.Errorf("idle = %+v, want died %+v and the survived gap reset", idle.Idle, want)
		}

		if idle.Drops != 1 || idle.ok() {
			t.Errorf("aggregate = %+v, want one drop, FAIL", idle)
		}

		if d := idle.detail(); !strings.Contains(d, "died after 0.04s gap: reset (had survived 0.02s)") {
			t.Errorf("detail %q lacks the death", d)
		}
	})

	t.Run("GOAWAY is server-closed", func(t *testing.T) {
		target := pingServer(t, cert, roots, true, 1, func(_ *net.TCPConn, framer *http2.Framer) {
			_ = framer.WriteGoAway(0, http2.ErrCodeNo, nil)
			time.Sleep(50 * time.Millisecond)
		})

		idle, ev, ended := runIdle(t, target, 5*time.Second)
		if !ended || ev.Event != eventServerClosed || ev.Class != "" {
			t.Fatalf("event = %+v, want server-closed", ev)
		}

		if idle.ServerClosed != 1 || idle.Drops != 0 || idle.Idle.Died.How != eventServerClosed || !idle.ok() {
			t.Errorf("aggregate = %+v idle %+v, want server_closed=1, ok", idle, idle.Idle)
		}
	})

	t.Run("unanswered PING is a timeout", func(t *testing.T) {
		target := pingServer(t, cert, roots, false, -1, nil)

		idle, ev, ended := runIdle(t, target, 5*time.Second)
		if !ended || ev.Event != eventDrop || ev.Class != classTimeout || ev.GapS != 0 {
			t.Fatalf("event = %+v, want a timeout drop on the first PING", ev)
		}

		if idle.Losses != 1 || idle.Idle.Died.How != classTimeout || idle.ok() {
			t.Errorf("aggregate = %+v idle %+v, want one lost PING, FAIL", idle, idle.Idle)
		}
	})
}
