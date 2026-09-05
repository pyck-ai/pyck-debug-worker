package probe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// keyKind selects the key type of a generated certificate.
type keyKind int

const (
	keyECDSA keyKind = iota
	keyRSA
	keyEd25519
)

// certSpec describes a certificate to generate in memory.
type certSpec struct {
	cn        string
	dnsNames  []string
	notBefore time.Time
	notAfter  time.Time
	isCA      bool
	key       keyKind
	extra     []pkix.Extension
}

// newKey generates a signer of the requested kind.
func newKey(t *testing.T, kind keyKind) crypto.Signer {
	t.Helper()

	switch kind {
	case keyRSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa key: %v", err)
		}

		return key
	case keyEd25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 key: %v", err)
		}

		return key
	case keyECDSA:
		fallthrough
	default:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa key: %v", err)
		}

		return key
	}
}

// newCert generates a certificate. Passing a nil parent self-signs it.
func newCert(t *testing.T, spec certSpec, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	key := newKey(t, spec.key)

	if spec.notBefore.IsZero() {
		spec.notBefore = time.Now().Add(-time.Hour)
	}

	if spec.notAfter.IsZero() {
		spec.notAfter = time.Now().Add(90 * 24 * time.Hour)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: spec.cn},
		DNSNames:              spec.dnsNames,
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       spec.extra,
	}

	if spec.isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}

	if parent == nil {
		parent, parentKey = tmpl, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert, key
}

// newChain generates a CA and a leaf signed by it.
func newChain(t *testing.T, leaf certSpec) (*x509.Certificate, *x509.Certificate) {
	t.Helper()

	ca, caKey := newCert(t, certSpec{cn: "pyck-debug-worker test CA", isCA: true}, nil, nil)
	cert, _ := newCert(t, leaf, ca, caKey)

	return cert, ca
}

// sctExtension builds an embedded SignedCertificateTimestampList with n
// entries. The entry bodies are opaque: nothing verifies them.
func sctExtension(t *testing.T, n int) pkix.Extension {
	t.Helper()

	var body []byte

	for range n {
		entry := []byte{0xde, 0xad, 0xbe, 0xef}
		body = append(body, byte(len(entry)>>8), byte(len(entry)))
		body = append(body, entry...)
	}

	list := append([]byte{byte(len(body) >> 8), byte(len(body))}, body...)

	value, err := asn1.Marshal(list)
	if err != nil {
		t.Fatalf("marshal sct list: %v", err)
	}

	return pkix.Extension{Id: sctExtensionOID, Value: value}
}

// testTarget is the target used by the probe tests.
var testTarget = target.Target{Host: "test.pyck.cloud", Port: 443, Kind: target.KindHTTPS}

func TestCertStage(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		spec     certSpec
		wantOK   bool
		contains []string
	}{
		{
			name:     "valid leaf",
			spec:     certSpec{cn: "test.pyck.cloud", dnsNames: []string{"test.pyck.cloud"}},
			wantOK:   true,
			contains: []string{"CN=test.pyck.cloud", "sans=1", "ECDSA256", "expires="},
		},
		{
			name: "expired",
			spec: certSpec{
				cn:        "test.pyck.cloud",
				dnsNames:  []string{"test.pyck.cloud"},
				notBefore: now.Add(-90 * 24 * time.Hour),
				notAfter:  now.Add(-24 * time.Hour),
			},
			wantOK:   false,
			contains: []string{"expired: NotAfter=", "(-1d)"},
		},
		{
			name: "not yet valid is not reported as expired",
			spec: certSpec{
				cn:        "test.pyck.cloud",
				dnsNames:  []string{"test.pyck.cloud"},
				notBefore: now.Add(24 * time.Hour),
				notAfter:  now.Add(90 * 24 * time.Hour),
			},
			wantOK:   false,
			contains: []string{"not yet valid: NotBefore="},
		},
		{
			name:     "hostname mismatch",
			spec:     certSpec{cn: "other.pyck.cloud", dnsNames: []string{"other.pyck.cloud"}},
			wantOK:   false,
			contains: []string{"hostname mismatch:", "CN=other.pyck.cloud"},
		},
		{
			name: "rsa key size",
			spec: certSpec{
				cn: "test.pyck.cloud", dnsNames: []string{"test.pyck.cloud"}, key: keyRSA,
			},
			wantOK:   true,
			contains: []string{"RSA2048"},
		},
		{
			name: "ed25519 key",
			spec: certSpec{
				cn: "test.pyck.cloud", dnsNames: []string{"test.pyck.cloud"}, key: keyEd25519,
			},
			wantOK:   true,
			contains: []string{"Ed25519"},
		},
		{
			name: "multiple sans are counted",
			spec: certSpec{
				cn:       "test.pyck.cloud",
				dnsNames: []string{"test.pyck.cloud", "www.test.pyck.cloud", "api.test.pyck.cloud"},
			},
			wantOK:   true,
			contains: []string{"sans=3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf, ca := newChain(t, tc.spec)
			state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, ca}}

			got := certStage(testTarget, state)
			if got.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v (detail %q)", got.OK, tc.wantOK, got.Detail)
			}

			if got.Stage != "cert" {
				t.Errorf("Stage = %q, want %q", got.Stage, "cert")
			}

			if got.Target != testTarget.Addr() {
				t.Errorf("Target = %q, want %q", got.Target, testTarget.Addr())
			}

			for _, want := range tc.contains {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("detail %q does not contain %q", got.Detail, want)
				}
			}
		})
	}
}

func TestCertStageExpiredAndMismatchedReportsBoth(t *testing.T) {
	leaf, ca := newChain(t, certSpec{
		cn:        "other.pyck.cloud",
		dnsNames:  []string{"other.pyck.cloud"},
		notBefore: time.Now().Add(-90 * 24 * time.Hour),
		notAfter:  time.Now().Add(-24 * time.Hour),
	})

	got := certStage(testTarget, tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, ca}})
	if got.OK {
		t.Fatalf("OK = true, want false")
	}

	for _, want := range []string{"expired: NotAfter=", "hostname mismatch:"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail %q does not contain %q", got.Detail, want)
		}
	}
}

func TestCertStageNoCertificate(t *testing.T) {
	got := certStage(testTarget, tls.ConnectionState{})
	if got.OK {
		t.Fatal("OK = true, want false")
	}

	if got.Detail != "no certificate presented" {
		t.Errorf("detail = %q", got.Detail)
	}
}
