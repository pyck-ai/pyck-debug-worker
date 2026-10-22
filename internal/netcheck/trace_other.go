//go:build !linux

package netcheck

import (
	"context"
	"errors"
	"net/netip"
)

// traceSupported is false: only Linux reports ICMP errors to an
// unprivileged UDP socket.
const traceSupported = false

// errTraceUnsupported is returned by traceRoute off Linux.
var errTraceUnsupported = errors.New("route trace needs Linux")

func traceRoute(context.Context, netip.Addr) (traceResult, error) {
	return traceResult{}, errTraceUnsupported
}
