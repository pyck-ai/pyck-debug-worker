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
		// The smb stage opens its own session first. If that one was accepted
		// and this one is not, the credential is not in question: the two use
		// independent SMB stacks, and only the submit stage's was refused.
		signal: "open smb session",
		meaning: "the print job's own SMB session was refused although the smb stage's session was accepted — " +
			"the credential is good; this is go-msrpc's session setup being rejected",
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
