//go:build linux

package netcheck

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// traceSupported is true: Linux queues ICMP errors for an unprivileged UDP
// socket with IP_RECVERR, which is all a tracepath-style trace needs.
const traceSupported = true

// Probe parameters.
const (
	// maxHops is the highest TTL probed.
	maxHops = 30
	// probesPerHop is how often a silent TTL is retried.
	probesPerHop = 2
	// probeTimeout is how long one probe waits for an answer.
	probeTimeout = 2 * time.Second
	// maxSilent ends the trace after this many TTLs in a row without any
	// answer: the destination usually drops UDP.
	maxSilent = 5
	// basePort is the first destination port; every probe uses the next
	// one, so an answer identifies its probe by the port it quotes.
	basePort = 33434
	// udpIPHeaders is the IPv4 plus UDP header size.
	udpIPHeaders = 28
	// minMTU is the IPv4 minimum, the floor when an MTU error carries none.
	minMTU = 576
	// pollStep bounds one wait so a cancelled ctx is noticed.
	pollStep = 100 * time.Millisecond
	// sizeofSockExtendedErr is sizeof(struct sock_extended_err).
	sizeofSockExtendedErr = 16
)

// errNoIPv4 is a trace to a non-IPv4 address.
var errNoIPv4 = errors.New("route trace needs an IPv4 address")

// replyKind is what an ICMP error says about a probe.
type replyKind int

const (
	// replyIgnore is anything not about the probe's path.
	replyIgnore replyKind = iota
	// replyHop is a TTL exceeded: a router on the way.
	replyHop
	// replyReached is a port unreachable from the destination itself.
	replyReached
	// replyUnreachable is any other destination unreachable: the path ends.
	replyUnreachable
	// replyMTU is a too-big packet; info is the MTU to use.
	replyMTU
)

// recvErr is one entry of the socket's error queue.
type recvErr struct {
	errno    syscall.Errno
	origin   uint8
	icmpType uint8
	icmpCode uint8
	info     uint32
	offender netip.Addr
}

// kind classifies the error.
func (e recvErr) kind() replyKind {
	switch {
	case e.errno == unix.EMSGSIZE:
		return replyMTU
	case e.origin != unix.SO_EE_ORIGIN_ICMP:
		return replyIgnore
	case e.icmpType == 11:
		return replyHop
	case e.icmpType == 3 && e.icmpCode == 3:
		return replyReached
	case e.icmpType == 3:
		return replyUnreachable
	}

	return replyIgnore
}

// parseRecvErr extracts the IP_RECVERR control message: struct
// sock_extended_err followed by the offender's struct sockaddr_in.
func parseRecvErr(oob []byte) (recvErr, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return recvErr{}, false
	}

	for _, m := range msgs {
		if m.Header.Level != unix.SOL_IP || m.Header.Type != unix.IP_RECVERR || len(m.Data) < sizeofSockExtendedErr {
			continue
		}

		d := m.Data
		e := recvErr{
			errno:    syscall.Errno(binary.NativeEndian.Uint32(d[0:4])),
			origin:   d[4],
			icmpType: d[5],
			icmpCode: d[6],
			info:     binary.NativeEndian.Uint32(d[8:12]),
		}

		// sockaddr_in: family, port, 4 address bytes.
		if sa := d[sizeofSockExtendedErr:]; len(sa) >= 8 && binary.NativeEndian.Uint16(sa[0:2]) == unix.AF_INET {
			e.offender = netip.AddrFrom4([4]byte(sa[4:8]))
		}

		return e, true
	}

	return recvErr{}, false
}

// traceRoute probes dst with UDP datagrams of increasing TTL and reads the
// routers' ICMP errors from the socket's error queue, like tracepath: no raw
// socket, no privilege. Probes carry DF and start at the route's MTU; a
// fragmentation-needed answer lowers it, which is how the path MTU is found.
func traceRoute(ctx context.Context, dst netip.Addr) (traceResult, error) {
	if !dst.Is4() {
		return traceResult{}, errNoIPv4
	}

	mtu, err := routeMTU(dst)
	if err != nil {
		return traceResult{}, err
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return traceResult{}, fmt.Errorf("trace socket: %w", err)
	}

	defer unix.Close(fd)

	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVERR, 1); err != nil {
		return traceResult{}, fmt.Errorf("trace IP_RECVERR: %w", err)
	}

	// PROBE sets DF but ignores the cached path MTU; older kernels fall
	// back to DO.
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE); err != nil {
		if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
			return traceResult{}, fmt.Errorf("trace IP_MTU_DISCOVER: %w", err)
		}
	}

	tr := tracer{fd: fd, dst: dst.As4(), mtu: mtu}

	return tr.run(ctx)
}

// routeMTU is the MTU of the route to dst, read from a connected UDP socket.
func routeMTU(dst netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("trace socket: %w", err)
	}

	defer unix.Close(fd)

	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: basePort, Addr: dst.As4()}); err != nil {
		return 0, fmt.Errorf("trace route: %w", err)
	}

	mtu, err := unix.GetsockoptInt(fd, unix.SOL_IP, unix.IP_MTU)
	if err != nil {
		return 0, fmt.Errorf("trace IP_MTU: %w", err)
	}

	return mtu, nil
}

// tracer is one trace in progress.
type tracer struct {
	fd    int
	dst   [4]byte
	mtu   int
	probe int
}

// run probes TTL 1 upwards until the destination answers, a router declares
// it unreachable, maxSilent TTLs stay silent or maxHops is reached.
func (tr *tracer) run(ctx context.Context) (traceResult, error) {
	res := traceResult{}
	silent := 0

	for ttl := 1; ttl <= maxHops && silent < maxSilent; ttl++ {
		if err := unix.SetsockoptInt(tr.fd, unix.SOL_IP, unix.IP_TTL, ttl); err != nil {
			return res, fmt.Errorf("trace IP_TTL: %w", err)
		}

		hop, kind, err := tr.hop(ctx, ttl)
		res.hops = append(res.hops, hop)
		res.pmtu = tr.mtu

		if err != nil {
			return res, err
		}

		switch {
		case kind == replyReached:
			res.reached = true

			return res, nil
		case kind == replyUnreachable:
			return res, nil
		case hop.IP == "":
			silent++
		default:
			silent = 0
		}
	}

	return res, nil
}

// hop probes one TTL until something answers or probesPerHop probes stayed
// silent. An MTU error lowers the MTU and resends without counting a try.
func (tr *tracer) hop(ctx context.Context, ttl int) (traceHop, replyKind, error) {
	hop := traceHop{TTL: ttl}

	for try := 0; try < probesPerHop; {
		port := basePort + tr.probe
		tr.probe++

		payload := make([]byte, tr.mtu-udpIPHeaders)
		sent := time.Now()

		err := unix.Sendto(tr.fd, payload, 0, &unix.SockaddrInet4{Port: port, Addr: tr.dst})
		if errors.Is(err, unix.EMSGSIZE) {
			// Larger than the local route allows: the error queue says by
			// how much.
			if !tr.lower(tr.drainMTU()) {
				try++
			}

			continue
		}

		if err != nil {
			return hop, replyIgnore, fmt.Errorf("trace send: %w", err)
		}

		e, rtt, ok, err := tr.wait(ctx, port, sent)
		if err != nil {
			return hop, replyIgnore, err
		}

		if !ok {
			try++

			continue
		}

		if kind := e.kind(); kind == replyMTU {
			if !tr.lower(e.info) {
				try++
			}

			continue
		}

		hop.IP = e.offender.String()
		hop.RTTMS = round(ms(rtt))
		hop.Carrier = carrierOf(e.offender)

		return hop, e.kind(), nil
	}

	return hop, replyIgnore, nil
}

// lower drops the probe MTU to mtu or, when mtu says nothing useful, by a
// header's worth, never below minMTU. It reports whether the MTU dropped.
func (tr *tracer) lower(mtu uint32) bool {
	old := tr.mtu

	if mtu >= minMTU && int(mtu) < tr.mtu {
		tr.mtu = int(mtu)
	} else {
		tr.mtu = max(minMTU, tr.mtu-udpIPHeaders)
	}

	return tr.mtu < old
}

// drainMTU reads the error queue for the MTU of a local EMSGSIZE.
func (tr *tracer) drainMTU() uint32 {
	var mtu uint32

	for {
		e, _, ok := tr.recv()
		if !ok {
			return mtu
		}

		if e.kind() == replyMTU {
			mtu = e.info
		}
	}
}

// wait waits for the error queue entry answering the probe sent to port.
// Answers to earlier probes are skipped. It reports false when the probe
// stayed unanswered.
func (tr *tracer) wait(ctx context.Context, port int, sent time.Time) (recvErr, time.Duration, bool, error) {
	deadline := sent.Add(probeTimeout)

	for {
		if ctx.Err() != nil {
			return recvErr{}, 0, false, ctx.Err()
		}

		left := time.Until(deadline)
		if left <= 0 {
			return recvErr{}, 0, false, nil
		}

		fds := []unix.PollFd{{Fd: int32(tr.fd), Events: unix.POLLIN}} //nolint:gosec // fd fits an int32
		if _, err := unix.Poll(fds, int(min(left, pollStep)/time.Millisecond)+1); err != nil && !errors.Is(err, unix.EINTR) {
			return recvErr{}, 0, false, fmt.Errorf("trace poll: %w", err)
		}

		if fds[0].Revents&unix.POLLIN != 0 {
			// A datagram back from the destination: not expected, drop it.
			_, _, _ = unix.Recvfrom(tr.fd, make([]byte, 1), unix.MSG_DONTWAIT)
		}

		if fds[0].Revents&unix.POLLERR == 0 {
			continue
		}

		for {
			e, to, ok := tr.recv()
			if !ok {
				break
			}

			if to == port {
				return e, time.Since(sent), true, nil
			}
		}
	}
}

// recv takes one entry off the error queue, with the destination port of the
// probe it answers.
func (tr *tracer) recv() (recvErr, int, bool) {
	oob := make([]byte, 512)

	_, oobn, _, from, err := unix.Recvmsg(tr.fd, make([]byte, 64), oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil {
		return recvErr{}, 0, false
	}

	e, ok := parseRecvErr(oob[:oobn])
	if !ok {
		return recvErr{}, 0, true
	}

	sa, _ := from.(*unix.SockaddrInet4)
	if sa == nil {
		return e, 0, true
	}

	return e, sa.Port, true
}
