package probe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	"github.com/pyck-ai/pyck-debug-worker/internal/report"
	"github.com/pyck-ai/pyck-debug-worker/internal/target"
)

// orgIDClaim is Zitadel's resource-owner claim, the organisation the user
// belongs to.
const orgIDClaim = "urn:zitadel:iam:user:resourceowner:id"

// How a tenant id was arrived at.
const (
	viaJWTClaim = "jwt-claim"
	viaComputed = "computed"
	viaAPI      = "api"
)

// tenant is a resolved tenant identity.
type tenant struct {
	id   string
	name string
	via  string
}

// jwtClaims are the only claims this tool reads.
type jwtClaims struct {
	TenantID string `json:"pyck_tenant_id"`
	Issuer   string `json:"iss"`
	OrgID    string `json:"urn:zitadel:iam:user:resourceowner:id"`
}

// pyckStages resolves the pyck identity behind the token.
//
// The gate is a token being present: with no credential there is nothing to
// authenticate and the stages print nothing at all. The binary never mints a
// token — pyck has no client_credentials grant.
func pyckStages(ctx context.Context, tgt target.Target, opts Options) []report.Result {
	if opts.Token.IsZero() {
		return nil
	}

	// A JWT carries the answer already. Decoding it offline avoids a network
	// call, so there is no auth stage on this path: nothing was asked of the
	// server, and a stage that did not run prints nothing.
	if claims, ok := decodeJWT(opts.Token.Reveal()); ok {
		return tenantResults(tgt, tenantFromClaims(claims), opts)
	}

	return patStages(ctx, tgt, opts)
}

// tenantResults renders the tenant stage and the cross-check that follows it.
func tenantResults(tgt target.Target, resolved tenant, opts Options) []report.Result {
	results := []report.Result{
		stage(tgt, "tenant", func() (bool, string) {
			if resolved.id == "" {
				return false, "no tenant id in the token: neither pyck_tenant_id nor " + orgIDClaim
			}

			return true, tenantDetail(resolved)
		}),
	}

	if resolved.id == "" {
		return results
	}

	if check, ok := crossCheck(tgt, resolved, opts); ok {
		results = append(results, check)
	}

	return results
}

// tenantDetail renders the resolved identity.
func tenantDetail(resolved tenant) string {
	detail := resolved.id

	if resolved.name != "" {
		detail += ` "` + resolved.name + `"`
	}

	return detail + " via=" + resolved.via
}

// crossCheck compares the resolved tenant against the values that were handed
// to us. PYCK_API_TENANT_ID is an input, never a derivation, and
// TEMPORAL_NAMESPACE is the tenant uuid — a mismatch between what the operator
// configured and who the credential actually is is the single highest-value
// signal this tool produces.
//
// The second return is false when neither value is set, in which case there is
// nothing to compare and the stage stays silent.
func crossCheck(tgt target.Target, resolved tenant, opts Options) (report.Result, bool) {
	type input struct {
		name  string
		value string
	}

	var present []input

	for _, in := range []input{
		{name: "TEMPORAL_NAMESPACE", value: opts.TemporalNamespace},
		{name: "--namespace", value: opts.NamespaceFlag},
		{name: "PYCK_API_TENANT_ID", value: opts.ExpectedTenantID},
	} {
		if in.value != "" {
			present = append(present, in)
		}
	}

	if len(present) == 0 {
		return report.Result{}, false
	}

	return stage(tgt, "tenant", func() (bool, string) {
		var (
			agree    []string
			mismatch []string
		)

		for _, in := range present {
			if strings.EqualFold(in.value, resolved.id) {
				agree = append(agree, "== "+in.name)

				continue
			}

			mismatch = append(mismatch, in.name+"="+in.value+" != resolved "+resolved.id)
		}

		if len(mismatch) > 0 {
			return false, strings.Join(mismatch, "; ")
		}

		return true, strings.Join(agree, " ")
	}), true
}

// tenantFromClaims applies the offline resolution order: the explicit claim
// first, then the two-stage UUIDv5 derivation.
func tenantFromClaims(claims jwtClaims) tenant {
	if claims.TenantID != "" {
		return tenant{id: claims.TenantID, via: viaJWTClaim}
	}

	if claims.Issuer == "" || claims.OrgID == "" {
		return tenant{via: viaComputed}
	}

	return tenant{id: computeTenantUUID(claims.Issuer, claims.OrgID).String(), via: viaComputed}
}

// computeTenantUUID derives a tenant id the way the pyck backend does: a
// UUIDv5 of the organisation id inside a namespace that is itself a UUIDv5 of
// the issuer (pyck/backend/common/authn/uuid.go).
func computeTenantUUID(issuer, orgID string) uuid.UUID {
	return uuid.NewSHA1(uuid.NewSHA1(uuid.NameSpaceOID, []byte(issuer)), []byte(orgID))
}

// decodeJWT reports whether the token is a JWT and returns the claims it
// carries.
//
// The signature is deliberately not verified: this tool reads the token it was
// given to find out who it claims to be, it does not accept it as proof of
// anything. Doing it with the standard library keeps a JWT dependency out of a
// diagnostic binary.
func decodeJWT(token string) (jwtClaims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, false
	}

	// The header must be a JSON object too, otherwise any string with two dots
	// in it would be read as a token.
	if _, ok := decodeJWTSegment[map[string]json.RawMessage](parts[0]); !ok {
		return jwtClaims{}, false
	}

	claims, ok := decodeJWTSegment[jwtClaims](parts[1])
	if !ok {
		return jwtClaims{}, false
	}

	return claims, true
}

// decodeJWTSegment base64url-decodes one segment and unmarshals it.
func decodeJWTSegment[T any](segment string) (T, bool) {
	var out T

	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return out, false
	}

	if err := json.Unmarshal(raw, &out); err != nil {
		return out, false
	}

	return out, true
}
