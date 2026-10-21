//go:build linux

package netcheck

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// tcpInfo is the subset of the kernel's TCP_INFO the long connection records.
type tcpInfo struct {
	RTT          time.Duration
	RTTVar       time.Duration
	TotalRetrans uint32
}

// readTCPInfo reads TCP_INFO from conn. It reports false if the socket could
// not be queried.
func readTCPInfo(conn *net.TCPConn) (tcpInfo, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return tcpInfo{}, false
	}

	var (
		info   *unix.TCPInfo
		sysErr error
	)

	err = raw.Control(func(fd uintptr) {
		info, sysErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) //nolint:gosec // fd fits an int
	})
	if err != nil || sysErr != nil {
		return tcpInfo{}, false
	}

	return tcpInfo{
		RTT:          time.Duration(info.Rtt) * time.Microsecond,
		RTTVar:       time.Duration(info.Rttvar) * time.Microsecond,
		TotalRetrans: info.Total_retrans,
	}, true
}
