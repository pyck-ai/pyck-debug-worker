package printcheck

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
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

func TestClassifyDeadlineClaimsOnlyTheBudget(t *testing.T) {
	// The entry this replaces named the SMB2 handshake as the cause of any
	// deadline anywhere in the stage. On the log that prompted the change the
	// deadline came from an RPC bind that could not write, so the claim was
	// wrong. A bare deadline must now say where to look and nothing else.
	err := errors.New("bind: write packet: write buffer: context deadline exceeded")

	got := classify(err)

	if !strings.Contains(got, "exceeded its "+submitTimeout.String()+" budget") {
		t.Errorf("classify() = %q, want the budget verdict", got)
	}

	for _, unwanted := range []string{"SMB2 handshake", "look at the print server", "concurrent SMB session"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("classify() = %q still asserts %q for a bare deadline", got, unwanted)
		}
	}
}

func TestClassifyDNS(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			// The pipe transport's failure in the real customer log.
			name: "resolver timeout",
			err:  errors.New("dial: lookup server address: lookup PRINT01.AD.EXAMPLE.COM: i/o timeout"),
			want: "did not resolve",
		},
		{
			name: "name does not exist",
			err:  errors.New("dial tcp: lookup PRINT01.AD.EXAMPLE.COM: no such host"),
			want: "does not exist in DNS",
		},
		{
			// "i/o timeout" without the resolver's own prefix is a socket
			// read, not a lookup, and must not be reported as DNS.
			name: "a socket read timeout is not a DNS failure",
			err:  errors.New("read tcp 10.0.0.5:445: i/o timeout"),
			want: "read tcp 10.0.0.5:445: i/o timeout",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.err)

			if !strings.Contains(got, tc.want) {
				t.Errorf("classify() = %q, does not contain %q", got, tc.want)
			}

			if !strings.Contains(got, tc.err.Error()) {
				t.Errorf("classify() = %q dropped the original error", got)
			}
		})
	}
}

func TestClassifyPrefersDNSOverTheDeadline(t *testing.T) {
	// Both signals are present. The lookup is the specific one and must win:
	// this is precisely the shape that produced the wrong verdict before.
	err := errors.New("dial: lookup PRINT01.AD.EXAMPLE.COM: i/o timeout: context deadline exceeded")

	if got := classify(err); !strings.Contains(got, "did not resolve") {
		t.Errorf("classify() = %q, want the DNS verdict", got)
	}
}

func TestVerdictOfOmitsTheEvidence(t *testing.T) {
	// The submit stage puts this on its result line and emits the raw errors
	// separately, so the error text must not be appended here.
	err := errors.New("dial: lookup PRINT01.AD.EXAMPLE.COM: i/o timeout")

	got := verdictOf(err)

	if !strings.Contains(got, "did not resolve") {
		t.Errorf("verdictOf() = %q, want the DNS verdict", got)
	}

	if strings.Contains(got, err.Error()) {
		t.Errorf("verdictOf() = %q, want the verdict alone without the error text", got)
	}
}

func TestVerdictOfIsEmptyWhenNothingMatches(t *testing.T) {
	for _, err := range []error{nil, errors.New("something entirely unexpected")} {
		if got := verdictOf(err); got != "" {
			t.Errorf("verdictOf(%v) = %q, want empty", err, got)
		}
	}
}

func TestChainLines(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want []string
	}{
		{name: "nil", err: nil, want: nil},
		{
			name: "a lone error is its own single line",
			err:  errors.New("context deadline exceeded"),
			want: []string{"context deadline exceeded"},
		},
		{
			name: "each wrap contributes only what it added",
			err: fmt.Errorf("dial %s: %w", `ncacn_np:[\pipe\spoolss]`,
				fmt.Errorf("dial: lookup server address: %w",
					errors.New("lookup PRINT01.AD.EXAMPLE.COM: i/o timeout"))),
			want: []string{
				`dial ncacn_np:[\pipe\spoolss]`,
				"dial: lookup server address",
				"lookup PRINT01.AD.EXAMPLE.COM: i/o timeout",
			},
		},
		{
			// What connect() now returns when both transports fail: two
			// chains, depth-first, in the order they were attempted.
			name: "a joined error yields both chains, not the join itself",
			err: errors.Join(
				fmt.Errorf("%s: %w", transportPipe,
					fmt.Errorf("dial: %w", errors.New("lookup PRINT01: i/o timeout"))),
				fmt.Errorf("%s: %w", transportTCP,
					fmt.Errorf("bind spooler: %w", errors.New("write buffer: context deadline exceeded"))),
			),
			want: []string{
				"ncacn_np",
				"dial",
				"lookup PRINT01: i/o timeout",
				"ncacn_ip_tcp",
				"bind spooler",
				"write buffer: context deadline exceeded",
			},
		},
		{
			// A wrap that adds no text of its own is not a blank line.
			name: "empty frames are dropped",
			err:  fmt.Errorf("%w", errors.New("context deadline exceeded")),
			want: []string{"context deadline exceeded"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := chainLines(tc.err)

			if !slices.Equal(got, tc.want) {
				t.Errorf("chainLines() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestChainLinesAddsNoCommentary(t *testing.T) {
	// The operator asked for the libraries' output verbatim. Every line must
	// appear somewhere in the original error text, so nothing was invented.
	err := errors.Join(
		fmt.Errorf("%s: %w", transportPipe, errors.New("lookup PRINT01: i/o timeout")),
		fmt.Errorf("%s: %w", transportTCP, errors.New("write buffer: context deadline exceeded")),
	)

	for _, line := range chainLines(err) {
		if !strings.Contains(err.Error(), line) {
			t.Errorf("chainLines() produced %q, which is not in the original error", line)
		}
	}
}

func TestSubmitDetailSplitsTheVerdictFromTheEvidence(t *testing.T) {
	// The two underlying errors of the customer log's line 72.
	err := errors.Join(
		fmt.Errorf("%s: %w", transportPipe,
			fmt.Errorf("dial: lookup server address: %w",
				errors.New("lookup PRINT01.AD.EXAMPLE.COM: i/o timeout"))),
		fmt.Errorf("%s: %w", transportTCP,
			fmt.Errorf("bind spooler over %s: %w", transportTCP,
				errors.New("bind: write packet: write buffer: context deadline exceeded"))),
	)

	var stream bytes.Buffer

	detail := submitDetail(testLogger(&stream), err)

	// The result line carries the verdict alone: no raw error text, and in
	// particular no parenthesised nesting.
	if !strings.Contains(detail, "did not resolve") {
		t.Errorf("detail = %q, want the DNS verdict", detail)
	}

	if strings.ContainsAny(detail, "()") {
		t.Errorf("detail = %q still nests raw errors in parentheses", detail)
	}

	if strings.Contains(detail, "context deadline exceeded") {
		t.Errorf("detail = %q leaked raw library text onto the result line", detail)
	}

	// The evidence is on the stream instead, one error per line.
	logged := strings.Split(strings.TrimSpace(stream.String()), "\n")

	if len(logged) != len(chainLines(err)) {
		t.Fatalf("stream has %d lines, want one per error level (%d)", len(logged), len(chainLines(err)))
	}

	for _, want := range []string{
		"lookup PRINT01.AD.EXAMPLE.COM: i/o timeout",
		"bind: write packet: write buffer: context deadline exceeded",
	} {
		if !strings.Contains(stream.String(), want) {
			t.Errorf("stream is missing %q", want)
		}
	}
}

func TestSubmitDetailFallsBackToTheTopFrame(t *testing.T) {
	// Nothing in the taxonomy matches, so the most specific honest line is the
	// frame the stage itself added, not the whole flattened chain.
	err := fmt.Errorf("RpcStartDocPrinter: %w", errors.New("something entirely unexpected"))

	var stream bytes.Buffer

	if got := submitDetail(testLogger(&stream), err); got != "RpcStartDocPrinter" {
		t.Errorf("submitDetail() = %q, want the top frame alone", got)
	}
}

// testLogger renders like debugLogger but into buf, so a test can read what
// the operator would see on stderr.
func testLogger(buf *bytes.Buffer) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{
		Out:           buf,
		NoColor:       true,
		PartsOrder:    []string{zerolog.MessageFieldName},
		FieldsExclude: []string{componentField},
	})
}
