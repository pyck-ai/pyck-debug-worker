package netcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// idleGaps are the silences between the idle connection's PINGs: a fresh
// connection is pinged once, then after each gap in turn, and every
// idleGaps[len-1] after that. A variable only so the tests can run in
// milliseconds.
var idleGaps = []time.Duration{
	30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 30 * time.Minute,
}

// idleLoop keeps one HTTP/2 connection to t open that stays silent between
// PINGs after growing gaps, to find how long an idle connection survives the
// path's middleboxes. It reconnects with backoff whenever it is lost.
func idleLoop(ctx context.Context, t Target, agg *agg, store *store) {
	backoff := minBackoff

	for ctx.Err() == nil {
		// No TCP keepalives: they would keep middlebox state alive and hide
		// exactly what is measured.
		conn, err := dialH2(ctx, t, net.Dialer{KeepAlive: -1})
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			noteFailure(agg, store, t, modeIdle, err)

			if !sleep(ctx, backoff) {
				return
			}

			backoff = min(2*backoff, maxBackoff)

			continue
		}

		backoff = minBackoff

		ev, ok := idleSession(ctx, t, conn, agg)
		if !ok {
			return
		}

		_ = store.writeEvent(ev)
	}
}

// idleSession pings conn once, then after each idle gap, until a PING fails
// or ctx ends. It returns the drop or server-closed event, or false if ctx
// ended.
func idleSession(ctx context.Context, t Target, conn *longConn, agg *agg) (event, bool) {
	defer conn.cc.Close()

	started := time.Now()

	var gap, survived time.Duration

	agg.idleSurvived(t, 0)

	for i := 0; ; i++ {
		err := idlePing(ctx, t, conn, agg)

		switch {
		case ctx.Err() != nil:
			return event{}, false
		case err != nil:
			// The first PING follows the handshake directly: not idle yet.
			phase := phaseIdle
			if gap == 0 {
				phase = phaseTransfer
			}

			ev := ended(t, modeIdle, phase, started, conn, err, agg)
			ev.GapS = gap.Seconds()
			ev.SurvivedS = survived.Seconds()

			how := ev.Class
			if ev.Event == eventServerClosed {
				how = eventServerClosed
			}

			agg.idleDied(t, idleDeath{GapS: ev.GapS, SurvivedS: ev.SurvivedS, How: how})
			agg.idleSurvived(t, 0)

			return ev, true
		case gap > 0:
			survived = max(survived, gap)
			agg.idleSurvived(t, survived)
		}

		gap = idleGaps[min(i, len(idleGaps)-1)]

		if !sleep(ctx, gap) {
			return event{}, false
		}
	}
}

// idlePing sends one PING and records it. A PING not answered within
// deadAfter ends the connection, as on the long connection.
func idlePing(ctx context.Context, t Target, conn *longConn, agg *agg) error {
	pingCtx, cancel := context.WithTimeout(ctx, deadAfter)
	defer cancel()

	started := time.Now()

	err := conn.cc.Ping(pingCtx)

	switch {
	case err == nil:
		agg.ping(t, modeIdle, time.Since(started))

		return nil
	case ctx.Err() != nil:
		return err
	case errors.Is(err, context.DeadlineExceeded):
		agg.lostPing(t, modeIdle)

		return fmt.Errorf("%w for %s", errNoAnswer, deadAfter)
	}

	return err
}
