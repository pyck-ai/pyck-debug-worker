package printcheck

import (
	"errors"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		// want is a fragment of the verdict, not the whole detail: the
		// original error text is always appended as evidence.
		want string
	}{
		{name: "nil", err: nil, want: ""},
		{
			name: "no KDC",
			err:  errors.New("krb5: failed to communicate with KDC 10.0.0.1:88"),
			want: "no KDC reachable",
		},
		{
			// The single most common real failure: SSSD rotated the MSA key
			// and the unit is still holding the snapshot from start-up.
			name: "stale keytab",
			err:  errors.New("KDC_ERR_PREAUTH_FAILED Additional pre-authentication required"),
			want: "restart the unit",
		},
		{
			name: "account missing",
			err:  errors.New("KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found in Kerberos database"),
			want: "missing or disabled",
		},
		{
			name: "spn unknown",
			err:  errors.New("KDC_ERR_S_PRINCIPAL_UNKNOWN Server not found in Kerberos database"),
			want: "not domain-joined",
		},
		{
			name: "clock skew",
			err:  errors.New("KRB_AP_ERR_SKEW Clock skew too great"),
			want: "chronyc tracking",
		},
		{
			name: "no aes keys",
			err:  errors.New("KDC_ERR_ETYPE_NOSUPP KDC has no support for encryption type"),
			want: "msDS-SupportedEncryptionTypes",
		},
		{
			name: "fast quirk",
			err:  errors.New("KDC did not respond appropriately to FAST negotiation"),
			want: "DisablePAFXFAST",
		},
		{
			name: "session rejected after a valid ticket",
			err:  errors.New("smb: STATUS_LOGON_FAILURE"),
			want: "server rejected the session",
		},
		{
			name: "share name wrong",
			err:  errors.New("STATUS_BAD_NETWORK_NAME"),
			want: "does not exist under that name",
		},
		{
			name: "unrecognised errors are passed through untouched",
			err:  errors.New("something entirely unexpected"),
			want: "something entirely unexpected",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.err)

			if tc.err == nil {
				if got != "" {
					t.Fatalf("classify(nil) = %q, want empty", got)
				}

				return
			}

			if !strings.Contains(got, tc.want) {
				t.Errorf("classify() = %q, does not contain %q", got, tc.want)
			}

			// The evidence must survive alongside the verdict.
			if !strings.Contains(got, tc.err.Error()) {
				t.Errorf("classify() = %q dropped the original error", got)
			}
		})
	}
}

func TestClassifyPrefersTheSpecificSignal(t *testing.T) {
	// A KDC error that also mentions communication must not be reported as an
	// unreachable KDC.
	err := errors.New("krb5: AS exchange error: KDC_ERR_PREAUTH_FAILED")

	if got := classify(err); !strings.Contains(got, "restart the unit") {
		t.Errorf("classify() = %q, want the preauth verdict", got)
	}
}
