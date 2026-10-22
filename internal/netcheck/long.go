package netcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/http2"
)

// Long connection timing. Variables, not constants, only so the tests can run
// in seconds.
var (
	// pingInterval is how often a PING is sent.
	pingInterval = time.Second
	// pingTimeout is how long a PING may go unanswered before it counts as
	// lost.
	pingTimeout = 5 * time.Second
	// deadAfter declares the connection dropped when no PING was answered
	// for this long. Without it a black-holed connection would only die after
	// the kernel gives up retransmitting, many minutes later.
	deadAfter = 30 * time.Second
	// minBackoff and maxBackoff bound the reconnect backoff.
	minBackoff = time.Second
	maxBackoff = time.Minute
)

// errNoAnswer is the drop reason when PINGs stopped being answered.
var errNoAnswer = errors.New("no PING answered")

// errNotH2 is a handshake that did not negotiate HTTP/2.
var errNotH2 = errors.New("server did not negotiate h2")

// longConn is one established long connection.
//
// x/net/http2's client types are deprecated in favour of net/http's, which
// cannot send a PING; hence the staticcheck exemptions in this file.
type longConn struct {
	cc  *http2.ClientConn //nolint:staticcheck // see above
	tcp *net.TCPConn
}

// longLoop keeps one HTTP/2 connection to t open, pinging it, and reconnects
// with backoff whenever it is lost.
func longLoop(ctx context.Context, t Target, agg *agg, store *store) {
	backoff := minBackoff

	for ctx.Err() == nil {
		conn, err := dialLong(ctx, t)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			// An intercepted connection is not used: PINGs would measure
			// the middlebox, not the path to the server.
			noteFailure(agg, store, t, modeLong, err)

			if !sleep(ctx, backoff) {
				return
			}

			backoff = min(2*backoff, maxBackoff)

			continue
		}

		backoff = minBackoff

		ev, ok := session(ctx, t, conn, agg)
		if !ok {
			return
		}

		_ = store.writeEvent(ev)
	}
}

// dialLong connects, handshakes with ALPN h2 and starts an HTTP/2 client
// connection.
func dialLong(ctx context.Context, t Target) (*longConn, error) {
	return dialH2(ctx, t, net.Dialer{})
}

// dialH2 is dialLong with the given dialer.
func dialH2(ctx context.Context, t Target, dialer net.Dialer) (*longConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := dialer.DialContext(dialCtx, "tcp", t.addr())
	if err != nil {
		return nil, err
	}

	counted := &countConn{Conn: conn}
	tlsConn := tls.Client(counted, tlsConfig(t, http2.NextProtoTLS))

	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = conn.Close()

		return nil, withPhase(wrapHandshake(err), handshakePhase(counted))
	}

	if tlsConn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
		_ = conn.Close()

		return nil, errNotH2
	}

	cc, err := (&http2.Transport{}).NewClientConn(tlsConn) //nolint:staticcheck // see longConn
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	tcp, _ := conn.(*net.TCPConn)

	return &longConn{cc: cc, tcp: tcp}, nil
}

// pingResult is one finished PING.
type pingResult struct {
	rtt time.Duration
	err error
}

// session pings conn until it dies or ctx ends. It returns the drop or
// server-closed event, or false if ctx ended.
func session(ctx context.Context, t Target, conn *longConn, agg *agg) (event, bool) {
	defer conn.cc.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	started := time.Now()
	lastAnswer := started

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	// Sized so in-flight PINGs can always deliver after the session ends.
	results := make(chan pingResult, int(pingTimeout/pingInterval)+2)

	var lastRetrans uint32

	if info, ok := readTCPInfo(conn.tcp); ok {
		lastRetrans = info.TotalRetrans
	}

	for {
		select {
		case <-ctx.Done():
			return event{}, false
		case <-ticker.C:
			if time.Since(lastAnswer) > deadAfter {
				return ended(t, modeLong, phaseTransfer, started, conn, fmt.Errorf("%w for %s", errNoAnswer, deadAfter), agg), true
			}

			go ping(ctx, conn.cc, results)

			if info, ok := readTCPInfo(conn.tcp); ok {
				agg.tcpInfo(t, info, info.TotalRetrans-lastRetrans)
				lastRetrans = info.TotalRetrans
			}
		case r := <-results:
			switch {
			case r.err == nil:
				lastAnswer = time.Now()
				agg.ping(t, modeLong, r.rtt)
			case ctx.Err() != nil:
				return event{}, false
			case errors.Is(r.err, context.DeadlineExceeded):
				agg.lostPing(t, modeLong)
			default:
				return ended(t, modeLong, phaseTransfer, started, conn, r.err, agg), true
			}
		}
	}
}

// ping sends one PING and reports its RTT.
func ping(ctx context.Context, cc *http2.ClientConn, results chan<- pingResult) { //nolint:staticcheck // see longConn
	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	started := time.Now()
	err := cc.Ping(ctx)

	results <- pingResult{rtt: time.Since(started), err: err}
}

// ended records the end of a long or idle connection. A connection the
// server sent GOAWAY on (nginx keepalive_time, a reload) is server-closed, not
// a drop. A reset is counted in phase.
func ended(t Target, mode, phase string, started time.Time, conn *longConn, err error, agg *agg) event {
	name := eventDrop

	// Closing without our own Close or Shutdown means a GOAWAY arrived.
	if st := conn.cc.State(); st.Closing && !errors.Is(err, errNoAnswer) {
		name = eventServerClosed
		agg.serverClosed(t, mode)
	} else {
		agg.drop(t, mode)
	}

	ev := newEvent(name, t)
	ev.Mode = mode
	ev.LifetimeS = round(time.Since(started).Seconds())
	ev.Error = err.Error()

	if name == eventDrop {
		ev.Class = dropClass(err)
	}

	if ev.Class == classReset {
		ev.Phase = phase
		agg.reset(t, mode, phase)
	}

	return ev
}

// dropClass is how a connection died: unanswered PINGs are a timeout.
func dropClass(err error) string {
	if errors.Is(err, errNoAnswer) {
		return classTimeout
	}

	return classify(err)
}

// sleep waits d, reporting false if ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
