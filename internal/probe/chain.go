package probe

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"strconv"
	"strings"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// sctExtensionOID is the embedded SignedCertificateTimestampList extension.
var sctExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// chainStage verifies the presented chain by hand.
//
// Path building and hostname matching are run independently so both faults are
// reported: x509 stops at the first one, which would hide a name mismatch
// behind an unknown authority (or the reverse).
//
// SCTs are counted, never verified — signature verification would pull in the
// CT log key material for no diagnostic gain. OCSP is not consulted at all:
// Let's Encrypt dropped OCSP URLs in May 2025 and switched the responders off
// in August 2025, so a staple never exists and any check would report a
// false failure against every healthy pyck endpoint.
//
// roots is nil in production, which means the system trust store. Tests pass an
// explicit pool so they need neither network nor a particular host trust store.
func chainStage(tgt target.Target, state tls.ConnectionState, roots *x509.CertPool) report.Result {
	return stage(tgt, "chain", func() (bool, string) {
		if len(state.PeerCertificates) == 0 {
			return false, "no certificate presented"
		}

		leaf := state.PeerCertificates[0]

		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}

		chains, verifyErr := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		})

		hostErr := leaf.VerifyHostname(tgt.Host)

		scts := " scts=" + strconv.Itoa(sctCount(state, leaf))

		if verifyErr == nil && hostErr == nil {
			return true, path(chains[0]) + " verified " + scts
		}

		var faults []string

		if verifyErr != nil {
			faults = append(faults, classify(verifyErr))
		}

		if hostErr != nil {
			faults = append(faults, classify(hostErr))
		}

		presented := path(state.PeerCertificates)
		if verifyErr == nil {
			presented = path(chains[0])
		}

		return false, presented + " " + scts + "  " + strings.Join(faults, "; ")
	})
}

// path renders a certificate chain as "leaf -> <issuer CN> -> <root CN>".
func path(chain []*x509.Certificate) string {
	parts := make([]string, 0, len(chain))
	parts = append(parts, "leaf")

	for _, cert := range chain[1:] {
		name := cert.Subject.CommonName
		if name == "" {
			name = cert.Subject.String()
		}

		parts = append(parts, name)
	}

	return strings.Join(parts, " -> ")
}

// sctCount counts the SCTs delivered in the handshake plus those embedded in
// the leaf certificate.
func sctCount(state tls.ConnectionState, leaf *x509.Certificate) int {
	return len(state.SignedCertificateTimestamps) + embeddedSCTs(leaf)
}

// embeddedSCTs counts the entries of the embedded SignedCertificateTimestampList
// extension. The list is a 16-bit length followed by 16-bit-prefixed entries;
// only the framing is walked, never the signatures.
func embeddedSCTs(leaf *x509.Certificate) int {
	var list []byte

	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(sctExtensionOID) {
			continue
		}

		if _, err := asn1.Unmarshal(ext.Value, &list); err != nil {
			return 0
		}

		break
	}

	if len(list) < 2 {
		return 0
	}

	body := list[2:]
	count := 0

	for len(body) >= 2 {
		size := int(body[0])<<8 | int(body[1])
		if len(body) < 2+size {
			break
		}

		body = body[2+size:]
		count++
	}

	return count
}
