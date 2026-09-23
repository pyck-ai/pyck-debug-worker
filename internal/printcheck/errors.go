package printcheck

import "strings"

// verdict pairs a signal found in an error string with what it actually means
// on an Active Directory network.
type verdict struct {
	signal  string
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
		// The submit stage is the only one with a deadline of its own, and it
		// wraps the whole ladder. This precedes the session entry below
		// because a stall during session setup carries both signals, and the
		// deadline is the more specific of the two.
		signal: "context deadline exceeded",
		meaning: "the print job did not complete within " + submitTimeout.String() +
			" — the SMB2 handshake to the print server stalled rather than failing; " +
			"the credential is not in question, since the earlier stages already proved it, " +
			"so look at the print server and the path to it for what stalls a second concurrent SMB session",
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
}

// classify renders an error as the taxonomy verdict plus the original text, so
// the operator gets both the diagnosis and the evidence for it.
func classify(err error) string {
	if err == nil {
		return ""
	}

	text := err.Error()

	for _, entry := range taxonomy {
		if strings.Contains(text, entry.signal) {
			return entry.meaning + " (" + text + ")"
		}
	}

	return text
}
