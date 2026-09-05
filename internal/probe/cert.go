package probe

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// dateLayout is the calendar date used in certificate details.
const dateLayout = "2006-01-02"

// certStage inspects the leaf certificate only; the path is the chain stage's
// job.
//
// It fails when the certificate is actually invalid — expired, not yet valid,
// or issued for a different name. Remaining lifetime is reported in the detail
// but never downgrades the status: there is no WARN, and a certificate with 20
// days left is not broken.
func certStage(tgt target.Target, state tls.ConnectionState) report.Result {
	return stage(tgt, "cert", func() (bool, string) {
		if len(state.PeerCertificates) == 0 {
			return false, "no certificate presented"
		}

		leaf := state.PeerCertificates[0]
		now := time.Now()
		info := certInfo(leaf, now)

		var faults []string

		// x509.Expired conflates "expired" and "not yet valid" into one reason
		// and one message, so decide it here against the actual bounds.
		switch {
		case now.Before(leaf.NotBefore):
			faults = append(faults, "not yet valid: NotBefore="+leaf.NotBefore.UTC().Format(dateLayout))
		case now.After(leaf.NotAfter):
			faults = append(faults, "expired: NotAfter="+leaf.NotAfter.UTC().Format(dateLayout))
		}

		if err := leaf.VerifyHostname(tgt.Host); err != nil {
			faults = append(faults, classify(err))
		}

		if len(faults) > 0 {
			return false, info + "  " + strings.Join(faults, "; ")
		}

		return true, info
	})
}

// certInfo renders CN, SAN count, key algorithm and expiry of a leaf.
func certInfo(leaf *x509.Certificate, now time.Time) string {
	cn := leaf.Subject.CommonName
	if cn == "" {
		cn = "-"
	}

	days := int(leaf.NotAfter.Sub(now).Hours() / 24)

	return fmt.Sprintf("CN=%s sans=%d %s expires=%s (%dd)",
		cn,
		sanCount(leaf),
		keyDescription(leaf.PublicKey),
		leaf.NotAfter.UTC().Format(dateLayout),
		days,
	)
}

// sanCount counts every subject alternative name on the certificate.
func sanCount(leaf *x509.Certificate) int {
	return len(leaf.DNSNames) + len(leaf.IPAddresses) + len(leaf.EmailAddresses) + len(leaf.URIs)
}

// keyDescription renders the public key algorithm and its size.
func keyDescription(pub any) string {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return "RSA" + strconv.Itoa(key.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA" + strconv.Itoa(key.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown-key"
	}
}
