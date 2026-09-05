package probe

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// dialTimeout bounds a single address so one blackholed IP cannot consume the
// whole cycle budget and starve the addresses queued behind it.
const dialTimeout = 5 * time.Second

// tcpStage dials every resolved address individually.
//
// Dialing the hostname would let Happy Eyeballs paper over a broken address:
// the connection succeeds and the broken family is never reported. One Result
// per address is the only way to see which one is down.
//
// The first address that connects is returned for the tls stage; every other
// connection is closed immediately.
func tcpStage(ctx context.Context, tgt target.Target, addrs []resolved) (net.Conn, []report.Result) {
	var (
		results []report.Result
		kept    net.Conn
		spare   []net.Conn
	)

	dialer := &net.Dialer{Timeout: dialTimeout}
	port := strconv.Itoa(tgt.Port)

	for _, family := range addrs {
		for _, addr := range family.addrs {
			hostPort := net.JoinHostPort(addr.String(), port)

			var conn net.Conn

			results = append(results, stage(tgt, "tcp("+family.family+")", func() (bool, string) {
				dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
				defer cancel()

				c, err := dialer.DialContext(dialCtx, dialNetwork(addr), hostPort)
				if err != nil {
					return false, hostPort + " " + classify(err)
				}

				conn = c

				return true, hostPort + " connected"
			}))

			switch {
			case conn == nil:
			case kept == nil:
				kept = conn
			default:
				spare = append(spare, conn)
			}
		}
	}

	closeAll(spare)

	return kept, results
}

// dialNetwork pins the dial to the address's family so the resolver is not
// consulted a second time.
func dialNetwork(addr netip.Addr) string {
	if addr.Is4() {
		return "tcp4"
	}

	return "tcp6"
}
