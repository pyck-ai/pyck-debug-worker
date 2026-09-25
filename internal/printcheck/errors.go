package printcheck

import (
	"errors"
	"strings"
)

// verdict pairs a signal found in an error string with what it actually means
// on an Active Directory network.
type verdict struct {
	signal string
	// and, when non-empty, must be present as well for the entry to match. It
	// exists for the one signal here that no single substring identifies: Go
	// renders a resolver timeout as "lookup <host>: i/o timeout", and
	// "i/o timeout" on its own is what every other timed-out socket read
	// renders too.
	and     string
	meaning string
}

// taxonomy is matched against the error text rather than with errors.As
// because gokrb5's krberror carries no Unwrap and does not export comparable
// sentinels: the KDC's error code only ever reaches us as a string.
//
// Order matters: the first match wins, so the specific entries precede the
// general ones.
var taxonomy = []verdict{
	{
		signal:  "failed to communicate with KDC",
		meaning: "no KDC reachable — check DNS and the firewall path to the domain controller",
	},
	{
		signal:  "KDC_ERR_PREAUTH_FAILED",
		meaning: "wrong or stale keytab — if the key rotated, restart the unit rather than debugging it",
	},
	{
		signal:  "KDC_ERR_C_PRINCIPAL_UNKNOWN",
		meaning: "the account is missing or disabled in the directory",
	},
	{
		signal:  "KDC_ERR_S_PRINCIPAL_UNKNOWN",
		meaning: "the SPN is unknown — wrong FQDN, or the print server is not domain-joined",
	},
	{
		signal:  "KRB_AP_ERR_SKEW",
		meaning: "clock skew over 300s — check chronyc tracking",
	},
	{
		signal:  "KDC_ERR_ETYPE_NOSUPP",
		meaning: "the account has no AES keys (RC4-only) — set msDS-SupportedEncryptionTypes to 24",
	},
	{
		signal:  "did not respond appropriately to FAST",
		meaning: "Active Directory FAST quirk — DisablePAFXFAST is not in effect",
	},
	{
		// A name that does not resolve is its own failure, distinguishable
		// from every other timeout by the resolver's own "lookup <host>:"
		// prefix, and actionable without knowing anything else about the
		// stage. The pairing is what makes it unambiguous: "i/o timeout"
		// alone is also how a timed-out socket read renders.
		signal:  "lookup ",
		and:     "i/o timeout",
		meaning: "the print server's name did not resolve — check this host's DNS and its search domains",
	},
	{
		signal:  "no such host",
		meaning: "the print server's name does not exist in DNS — check the name and this host's search domains",
	},
	{
		// Not a refusal, despite how this reads on the wire. A capture of the
		// stall shows NEGOTIATE sent and answered in under a millisecond and
		// then SESSION_SETUP never transmitted at all: go-msrpc asks its
		// Kerberos SSP for the token before it builds the request, and that
		// SSP runs a second Kerberos client of its own — the login P1 already
		// completed is not reused — so a KDC that does not answer stalls the
		// handshake with nothing on the wire. The reset that ends it arrives
		// later, from the server timing out a connection that went idle.
		signal: "open smb session",
		meaning: "the SMB2 handshake stalled before session setup was sent — nothing was refused; " +
			"go-msrpc runs its own second Kerberos client here, and its KDC exchange is what stalls, " +
			"so check this host's path to a KDC rather than the print server or the credential, " +
			"both of which the earlier stages already proved",
	},
	{
		signal:  "STATUS_LOGON_FAILURE",
		meaning: "the ticket was valid but the server rejected the session — account not permitted, or SMB policy",
	},
	{
		signal:  "STATUS_ACCESS_DENIED",
		meaning: "authenticated, but this account may not use that printer",
	},
	{
		signal:  "STATUS_BAD_NETWORK_NAME",
		meaning: "the share does not exist under that name",
	},
	{
		// Last, and deliberately says almost nothing. The submit stage is the
		// only one with a deadline of its own and it wraps the whole ladder,
		// so this signal appears for a DNS timeout, an RPC bind that could not
		// write, a KDC that never answered, and an SMB2 handshake that
		// stalled — indistinguishable from each other at this level. Until
		// v1.1.5 this entry named the SMB2 handshake as the cause, which was
		// a guess, and on the log that prompted this it was the wrong one:
		// the real failures were a DNS timeout and a bind write timeout. Every
		// entry above it is reached first when its own signal is present, so
		// what lands here is a bare deadline with nothing else to go on, and
		// what it says is where to look rather than what happened.
		signal: "context deadline exceeded",
		meaning: "P5 exceeded its " + submitTimeout.String() +
			" budget — the raw errors below say where it stopped",
	},
}

// classify renders an error as the taxonomy verdict plus the original text, so
// the operator gets both the diagnosis and the evidence for it.
//
// The text it appends is the error's own, flattened: it is the one-line
// summary. Where the full chain matters — the submit stage, whose errors nest
// two transports deep — chainLines renders it unflattened onto the debug
// stream instead, and this stays the single line the result column holds.
func classify(err error) string {
	if err == nil {
		return ""
	}

	text := err.Error()

	if entry, ok := match(text); ok {
		return entry.meaning + " (" + text + ")"
	}

	return text
}

// verdictOf returns the taxonomy's meaning for err on its own, with no error
// text appended. It is what the submit stage puts on its result line, because
// that stage emits the evidence separately rather than inline.
func verdictOf(err error) string {
	if err == nil {
		return ""
	}

	if entry, ok := match(err.Error()); ok {
		return entry.meaning
	}

	return ""
}

// match finds the first taxonomy entry whose signals are all present.
func match(text string) (verdict, bool) {
	for _, entry := range taxonomy {
		if !strings.Contains(text, entry.signal) {
			continue
		}

		if entry.and != "" && !strings.Contains(text, entry.and) {
			continue
		}

		return entry, true
	}

	return verdict{}, false
}

// chainLines walks err's tree and returns one line per level, each the text
// that level contributes and nothing else — no prefix, no commentary, no
// parentheses. A wrapped error's Error() repeats everything below it, so each
// line is trimmed of the suffix its children already account for; what remains
// is the frame that level added.
//
// Both errors.Unwrap shapes are followed: the single-error one, and the
// Unwrap() []error that errors.Join and the submit stage's own two-transport
// error produce. A tree therefore comes out depth-first, in the order the
// transports were attempted.
func chainLines(err error) []string {
	if err == nil {
		return nil
	}

	var lines []string

	switch unwrapped := err.(type) {
	case interface{ Unwrap() []error }:
		// A multi-error is pure aggregation: its own text is its children's,
		// joined. It contributes no line of its own, only its children's,
		// which keeps the two transports' chains adjacent and unprefixed.
		for _, child := range unwrapped.Unwrap() {
			lines = append(lines, chainLines(child)...)
		}
	default:
		child := errors.Unwrap(err)

		lines = append(lines, frame(err, child))
		lines = append(lines, chainLines(child)...)
	}

	return trimEmpty(lines)
}

// frame returns what err adds over the error it wraps: its own text with the
// child's already-included text removed. An error that wraps with %w and adds
// nothing of its own yields an empty string, which trimEmpty drops rather than
// printing as a blank line.
func frame(err error, child error) string {
	text := err.Error()

	if child != nil {
		text = strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(text, child.Error())), ":")
	}

	return strings.TrimSpace(text)
}

// trimEmpty drops the empty frames.
func trimEmpty(lines []string) []string {
	kept := lines[:0]

	for _, line := range lines {
		if line != "" {
			kept = append(kept, line)
		}
	}

	return kept
}
