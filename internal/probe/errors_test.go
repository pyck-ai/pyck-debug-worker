package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// opError wraps errno the way the net package does.
func opError(errno syscall.Errno) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp4",
		Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443},
		Err:  os.NewSyscallError("connect", errno),
	}
}

func TestClassify(t *testing.T) {
	now := time.Now()

	expired := &x509.Certificate{
		NotBefore: now.Add(-48 * time.Hour),
		NotAfter:  now.Add(-24 * time.Hour),
	}

	future := &x509.Certificate{
		NotBefore: now.Add(24 * time.Hour),
		NotAfter:  now.Add(48 * time.Hour),
	}

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: ""},
		{
			name: "deadline is a dropped SYN",
			err:  fmt.Errorf("dial: %w", context.DeadlineExceeded),
			want: "deadline exceeded before any response (SYN dropped, firewall)",
		},
		{name: "refused", err: opError(syscall.ECONNREFUSED), want: "connection refused"},
		{name: "timed out", err: opError(syscall.ETIMEDOUT), want: "connection timed out"},
		{name: "host unreachable", err: opError(syscall.EHOSTUNREACH), want: "host unreachable"},
		{
			name: "unknown authority",
			err:  x509.UnknownAuthorityError{},
			want: "unknown authority: check the CA bundle",
		},
		{
			name: "expired",
			err:  x509.CertificateInvalidError{Cert: expired, Reason: x509.Expired},
			want: "certificate expired: NotAfter=" + expired.NotAfter.UTC().Format(dateLayout),
		},
		{
			name: "not yet valid",
			err:  x509.CertificateInvalidError{Cert: future, Reason: x509.Expired},
			want: "certificate not yet valid: NotBefore=" + future.NotBefore.UTC().Format(dateLayout),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.err); got != tc.want {
				t.Errorf("classify() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyHostnameError(t *testing.T) {
	err := x509.HostnameError{Host: "test.pyck.cloud", Certificate: &x509.Certificate{}}

	got := classify(err)
	if !strings.HasPrefix(got, "hostname mismatch: ") {
		t.Errorf("classify() = %q, want a hostname mismatch prefix", got)
	}
}

func TestClassifyFallsBackToOpError(t *testing.T) {
	got := classify(opError(syscall.ENETUNREACH))
	if !strings.HasPrefix(got, "dial: ") {
		t.Errorf("classify() = %q, want the op prefix", got)
	}
}

func TestClassifyUnknownError(t *testing.T) {
	err := errors.New("something else entirely")
	if got := classify(err); got != err.Error() {
		t.Errorf("classify() = %q, want %q", got, err.Error())
	}
}

func TestNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "no such host", err: &net.DNSError{Err: "no such host", IsNotFound: true}, want: true},
		{name: "server misbehaving", err: &net.DNSError{Err: "server misbehaving"}, want: false},
		{name: "other", err: errors.New("boom"), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := notFound(tc.err); got != tc.want {
				t.Errorf("notFound() = %v, want %v", got, tc.want)
			}
		})
	}
}
