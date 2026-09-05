package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// classify turns a probe error into the verdict shown in the detail column.
// The mapping is the error taxonomy: the same underlying failure must always
// read the same way, so the summary alone is enough to act on.
func classify(err error) string {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline exceeded before any response (SYN dropped, firewall)"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ETIMEDOUT):
		return "connection timed out"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host unreachable"
	}

	if reason, ok := grpcReason(err); ok {
		return reason
	}

	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return "unknown authority: check the CA bundle"
	}

	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "hostname mismatch: " + hostname.Error()
	}

	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return certificateInvalidReason(invalid)
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op + ": " + opErr.Err.Error()
	}

	return err.Error()
}

// certificateInvalidReason disambiguates x509.Expired, which is returned both
// for a certificate that has expired and for one that is not valid yet, with
// the same message for either.
func certificateInvalidReason(err x509.CertificateInvalidError) string {
	if err.Reason != x509.Expired || err.Cert == nil {
		return err.Error()
	}

	now := time.Now()

	switch {
	case now.Before(err.Cert.NotBefore):
		return "certificate not yet valid: NotBefore=" + err.Cert.NotBefore.UTC().Format(dateLayout)
	case now.After(err.Cert.NotAfter):
		return "certificate expired: NotAfter=" + err.Cert.NotAfter.UTC().Format(dateLayout)
	default:
		return err.Error()
	}
}

// codeOf extracts the gRPC status code from an error.
//
// Temporal's serviceerror types expose Status() rather than GRPCStatus(), so
// neither status.Code nor status.FromError recognises them and every Temporal
// fault would otherwise fall through the taxonomy as an unclassified string.
func codeOf(err error) (codes.Code, bool) {
	if st, ok := status.FromError(err); ok {
		return st.Code(), true
	}

	var temporalErr interface{ Status() *status.Status }
	if errors.As(err, &temporalErr) {
		return temporalErr.Status().Code(), true
	}

	return codes.Unknown, false
}

// grpcReason renders a gRPC status per the error taxonomy. The second return
// reports whether err carried a status at all.
//
// ResourceExhausted means the endpoint is healthy but rate-limiting us. It is
// still surfaced as a failure by the caller, because the probe did not
// complete — the detail is what distinguishes it from an outage.
func grpcReason(err error) (string, bool) {
	code, ok := codeOf(err)
	if !ok {
		return "", false
	}

	message := err.Error()
	if st, ok := status.FromError(err); ok {
		message = st.Message()
	}

	switch code {
	case codes.Unauthenticated:
		return "unauthenticated: bad API key", true
	case codes.PermissionDenied:
		// PLAN reads this as "valid identity, wrong scope", but the live pyck
		// frontend also answers PermissionDenied for a plainly invalid key,
		// so the verdict must not vouch for the identity.
		return "permission denied: not authorised for this namespace (rejected key or wrong scope)", true
	case codes.ResourceExhausted:
		return "resource exhausted: rate-limited but healthy", true
	case codes.Unavailable:
		return "unavailable: " + message, true
	case codes.Unimplemented:
		return "unimplemented: " + message, true
	case codes.NotFound:
		return "not found: " + message, true
	case codes.DeadlineExceeded:
		return "deadline exceeded before any status (SYN dropped, firewall)", true
	default:
		return code.String() + ": " + message, true
	}
}
