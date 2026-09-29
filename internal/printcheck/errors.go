package printcheck

import "strings"

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
		meaning: "a hostname did not resolve — check this host's DNS and its search domains",
	},
	{
		signal:  "no such host",
		meaning: "a hostname does not exist in DNS — check the name and this host's search domains",
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
}

// classify renders an error as the taxonomy verdict plus the original text, so
// the operator gets both the diagnosis and the evidence for it.
//
// The text it appends is the error's own, flattened: every stage reports on a
// single result line, and this is that line's detail.
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
