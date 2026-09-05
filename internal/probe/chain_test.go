package probe

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"
)

// poolOf builds a root pool containing certs.
func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return pool
}

func TestChainStage(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		spec certSpec
		// trusted controls whether the generated CA is in the root pool.
		trusted  bool
		scts     [][]byte
		wantOK   bool
		contains []string
		absent   []string
	}{
		{
			name:     "verified against a trusted root",
			spec:     certSpec{cn: "test.pyck.cloud", dnsNames: []string{"test.pyck.cloud"}},
			trusted:  true,
			wantOK:   true,
			contains: []string{"leaf -> pyck-debug-worker test CA", "verified", "scts=0"},
		},
		{
			name:     "untrusted root",
			spec:     certSpec{cn: "test.pyck.cloud", dnsNames: []string{"test.pyck.cloud"}},
			trusted:  false,
			wantOK:   false,
			contains: []string{"unknown authority: check the CA bundle"},
			absent:   []string{"verified"},
		},
		{
			name:     "hostname mismatch is reported even when the path verifies",
			spec:     certSpec{cn: "other.pyck.cloud", dnsNames: []string{"other.pyck.cloud"}},
			trusted:  true,
			wantOK:   false,
			contains: []string{"leaf -> pyck-debug-worker test CA", "hostname mismatch:"},
		},
		{
			name: "expired is not reported as not-yet-valid",
			spec: certSpec{
				cn:        "test.pyck.cloud",
				dnsNames:  []string{"test.pyck.cloud"},
				notBefore: now.Add(-90 * 24 * time.Hour),
				notAfter:  now.Add(-24 * time.Hour),
			},
			trusted:  true,
			wantOK:   false,
			contains: []string{"certificate expired: NotAfter="},
			absent:   []string{"not yet valid"},
		},
		{
			name: "not yet valid is not reported as expired",
			spec: certSpec{
				cn:        "test.pyck.cloud",
				dnsNames:  []string{"test.pyck.cloud"},
				notBefore: now.Add(24 * time.Hour),
				notAfter:  now.Add(90 * 24 * time.Hour),
			},
			trusted:  true,
			wantOK:   false,
			contains: []string{"certificate not yet valid: NotBefore="},
			absent:   []string{"expired"},
		},
		{
			name: "embedded scts are counted",
			spec: certSpec{
				cn:       "test.pyck.cloud",
				dnsNames: []string{"test.pyck.cloud"},
				extra:    []pkix.Extension{sctExtension(t, 3)},
			},
			trusted:  true,
			wantOK:   true,
			contains: []string{"scts=3"},
		},
		{
			name:     "handshake scts are counted",
			spec:     certSpec{cn: "test.pyck.cloud", dnsNames: []string{"test.pyck.cloud"}},
			trusted:  true,
			scts:     [][]byte{{0x01}, {0x02}},
			wantOK:   true,
			contains: []string{"scts=2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf, ca := newChain(t, tc.spec)

			roots := x509.NewCertPool()
			if tc.trusted {
				roots = poolOf(ca)
			}

			state := tls.ConnectionState{
				PeerCertificates:            []*x509.Certificate{leaf, ca},
				SignedCertificateTimestamps: tc.scts,
			}

			got := chainStage(testTarget, state, roots)
			if got.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v (detail %q)", got.OK, tc.wantOK, got.Detail)
			}

			if got.Stage != "chain" {
				t.Errorf("Stage = %q, want %q", got.Stage, "chain")
			}

			for _, want := range tc.contains {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("detail %q does not contain %q", got.Detail, want)
				}
			}

			for _, unwanted := range tc.absent {
				if strings.Contains(got.Detail, unwanted) {
					t.Errorf("detail %q unexpectedly contains %q", got.Detail, unwanted)
				}
			}
		})
	}
}

func TestChainStageReportsPathAndHostnameFaultsIndependently(t *testing.T) {
	leaf, ca := newChain(t, certSpec{cn: "other.pyck.cloud", dnsNames: []string{"other.pyck.cloud"}})

	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, ca}}

	// Empty pool: the path cannot be built and the name does not match. Both
	// faults must appear, not just whichever x509 hits first.
	got := chainStage(testTarget, state, x509.NewCertPool())
	if got.OK {
		t.Fatal("OK = true, want false")
	}

	for _, want := range []string{"unknown authority: check the CA bundle", "hostname mismatch:"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail %q does not contain %q", got.Detail, want)
		}
	}
}

func TestChainStageNoCertificate(t *testing.T) {
	got := chainStage(testTarget, tls.ConnectionState{}, nil)
	if got.OK {
		t.Fatal("OK = true, want false")
	}

	if got.Detail != "no certificate presented" {
		t.Errorf("detail = %q", got.Detail)
	}
}

func TestEmbeddedSCTs(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{name: "none", want: 0},
		{name: "one", want: 1},
		{name: "five", want: 5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := certSpec{cn: "test.pyck.cloud", dnsNames: []string{"test.pyck.cloud"}}
			if tc.want > 0 {
				spec.extra = []pkix.Extension{sctExtension(t, tc.want)}
			}

			leaf, _ := newChain(t, spec)

			if got := embeddedSCTs(leaf); got != tc.want {
				t.Errorf("embeddedSCTs() = %d, want %d", got, tc.want)
			}
		})
	}
}
