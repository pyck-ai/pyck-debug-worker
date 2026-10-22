//go:build linux

package netcheck

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// cmsg encodes one SOL_IP control message the way the kernel lays it out.
func cmsg(typ int32, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	length := uint64(unix.CmsgLen(len(data)))

	if unix.SizeofCmsghdr == 16 {
		binary.NativeEndian.PutUint64(b[0:], length)
		binary.NativeEndian.PutUint32(b[8:], uint32(unix.SOL_IP))
		binary.NativeEndian.PutUint32(b[12:], uint32(typ))
	} else {
		binary.NativeEndian.PutUint32(b[0:], uint32(length))
		binary.NativeEndian.PutUint32(b[4:], uint32(unix.SOL_IP))
		binary.NativeEndian.PutUint32(b[8:], uint32(typ))
	}

	copy(b[unix.SizeofCmsghdr:], data)

	return b
}

// extendedErr encodes struct sock_extended_err plus the offender's
// sockaddr_in.
func extendedErr(errno syscall.Errno, origin, typ, code uint8, info uint32, offender netip.Addr) []byte {
	b := make([]byte, sizeofSockExtendedErr+16)
	binary.NativeEndian.PutUint32(b[0:], uint32(errno))
	b[4], b[5], b[6] = origin, typ, code
	binary.NativeEndian.PutUint32(b[8:], info)

	if offender.IsValid() {
		binary.NativeEndian.PutUint16(b[16:], unix.AF_INET)
		ip := offender.As4()
		copy(b[20:24], ip[:])
	}

	return b
}

func TestParseRecvErr(t *testing.T) {
	router := netip.MustParseAddr("59.43.1.1")

	tests := []struct {
		name     string
		oob      []byte
		kind     replyKind
		offender netip.Addr
		info     uint32
	}{
		{
			name:     "time exceeded",
			oob:      cmsg(unix.IP_RECVERR, extendedErr(unix.EHOSTUNREACH, unix.SO_EE_ORIGIN_ICMP, 11, 0, 0, router)),
			kind:     replyHop,
			offender: router,
		},
		{
			name:     "port unreachable from the destination",
			oob:      cmsg(unix.IP_RECVERR, extendedErr(unix.ECONNREFUSED, unix.SO_EE_ORIGIN_ICMP, 3, 3, 0, router)),
			kind:     replyReached,
			offender: router,
		},
		{
			name:     "admin prohibited",
			oob:      cmsg(unix.IP_RECVERR, extendedErr(unix.EHOSTUNREACH, unix.SO_EE_ORIGIN_ICMP, 3, 13, 0, router)),
			kind:     replyUnreachable,
			offender: router,
		},
		{
			name:     "fragmentation needed",
			oob:      cmsg(unix.IP_RECVERR, extendedErr(unix.EMSGSIZE, unix.SO_EE_ORIGIN_ICMP, 3, 4, 1400, router)),
			kind:     replyMTU,
			offender: router,
			info:     1400,
		},
		{
			name: "local MTU error has no offender",
			oob:  cmsg(unix.IP_RECVERR, extendedErr(unix.EMSGSIZE, unix.SO_EE_ORIGIN_LOCAL, 0, 0, 1280, netip.Addr{})),
			kind: replyMTU,
			info: 1280,
		},
		{
			name: "other control messages are skipped",
			oob: append(cmsg(unix.IP_TTL, []byte{64, 0, 0, 0}),
				cmsg(unix.IP_RECVERR, extendedErr(unix.EHOSTUNREACH, unix.SO_EE_ORIGIN_ICMP, 11, 0, 0, router))...),
			kind:     replyHop,
			offender: router,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := parseRecvErr(tc.oob)
			if !ok {
				t.Fatal("not parsed")
			}

			if e.kind() != tc.kind || e.offender != tc.offender || e.info != tc.info {
				t.Errorf("parsed %+v kind %v, want kind %v offender %v info %d", e, e.kind(), tc.kind, tc.offender, tc.info)
			}
		})
	}

	if _, ok := parseRecvErr(cmsg(unix.IP_TTL, []byte{64, 0, 0, 0})); ok {
		t.Error("no IP_RECVERR message must not parse")
	}
}

func TestTracerLower(t *testing.T) {
	tr := tracer{mtu: 1500}

	if !tr.lower(1400) || tr.mtu != 1400 {
		t.Errorf("lower(1400) → %d", tr.mtu)
	}

	if !tr.lower(0) || tr.mtu != 1372 {
		t.Errorf("lower(0) → %d, want one header less", tr.mtu)
	}

	tr.mtu = minMTU
	if tr.lower(0) || tr.mtu != minMTU {
		t.Errorf("lower at the minimum → %d, must not drop further", tr.mtu)
	}
}

func TestFlowPort(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")

	if first, again := flowPort(a), flowPort(netip.MustParseAddr("192.0.2.10")); first != again {
		t.Errorf("flowPort is not stable: %d, then %d", first, again)
	}

	for _, ip := range []netip.Addr{a, b} {
		if p := flowPort(ip); p < srcPortBase || p >= srcPortBase+srcPorts {
			t.Errorf("flowPort(%s) = %d, out of range", ip, p)
		}
	}
}

// TestTraceLoopback runs a real, unprivileged trace: on loopback the
// destination answers the first probe with port unreachable.
func TestTraceLoopback(t *testing.T) {
	res, err := traceRoute(context.Background(), netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}

	if !res.reached || len(res.hops) != 1 || res.hops[0].IP != "127.0.0.1" || res.hops[0].TTL != 1 || res.pmtu <= 0 {
		t.Errorf("trace = %+v, want the destination at TTL 1 and an MTU", res)
	}

	if _, err := traceRoute(context.Background(), netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Error("IPv6 trace did not fail")
	}
}

func TestTraceLoopStartup(t *testing.T) {
	target := Target{Host: "localhost", IP: netip.MustParseAddr("127.0.0.1"), Port: port}

	dir := t.TempDir()

	var out bytes.Buffer

	sh := &shared{agg: newAgg(), store: newStore(dir, testHeader()), p: &printer{out: &out}, jumps: newJumps()}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	traceLoop(ctx, target, sh)
	sh.store.close()

	if line := out.String(); !strings.Contains(line, "nc-trace") || !strings.Contains(line, "startup  hops=1  reached") {
		t.Errorf("stdout %q, want one startup trace line", line)
	}

	lines := readLines(t, filepath.Join(dir, time.Now().UTC().Format(dayLayout)+fileExt))
	if len(lines) != 2 || lines[1]["type"] != "trace" || lines[1]["reason"] != reasonStartup || lines[1]["reached"] != true {
		t.Errorf("file = %v, want the header and one trace record", lines)
	}
}
