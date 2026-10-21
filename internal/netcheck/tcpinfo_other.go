//go:build !linux

package netcheck

import (
	"net"
	"time"
)

// tcpInfo is the subset of the kernel's TCP_INFO the long connection records.
type tcpInfo struct {
	RTT          time.Duration
	RTTVar       time.Duration
	TotalRetrans uint32
}

// readTCPInfo is unavailable outside Linux.
func readTCPInfo(*net.TCPConn) (tcpInfo, bool) {
	return tcpInfo{}, false
}
