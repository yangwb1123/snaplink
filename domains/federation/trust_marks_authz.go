package federation

import (
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// checkMarkBindings runs the slice-4b claim bindings on a signature-VALIDATED
// mark: sub==RP (confused-deputy), SIGNED trust_mark_type==reqType
// (authoritative), and freshness (iat/exp within skew). Shared by the
// configured and federation-resolved paths so the invariants are identical
// regardless of how the issuer was authorized.
func (r *trustMarkRequirement) checkMarkBindings(claims trustMarkClaims, leafEntityID, reqType string, now time.Time) error {
	// sub == the RP/leaf entity ID: the confused-deputy guard. A genuine mark
	// ABOUT a DIFFERENT subject must NOT admit this RP.
	if claims.Sub != leafEntityID {
		return fmt.Errorf("trust mark sub %q != leaf entity id %q", claims.Sub, leafEntityID)
	}
	// The SIGNED trust_mark_type is AUTHORITATIVE: it MUST equal reqType. This
	// also makes the issuer's per-type authorization (checked on reqType in
	// resolveIssuerKeys) an authorization on the SIGNED type — a wrapper cannot
	// relabel a mark of another type into reqType.
	if claims.TrustMarkType != reqType {
		return fmt.Errorf("signed trust_mark_type %q != required %q", claims.TrustMarkType, reqType)
	}
	// Freshness: iat REQUIRED and not in the future; exp (if present) not
	// expired. Both bounded by the configured skew (clock drift only).
	if err := r.checkTrustMarkFresh(claims, now); err != nil {
		return err
	}
	return nil
}

// acquireIssuerResolveSlot tries to take one of the bounded GLOBAL nested-
// resolution slots WITHOUT blocking. true ⇒ a slot was acquired (the caller MUST
// releaseIssuerResolveSlot); false ⇒ the semaphore is saturated (fail-closed:
// the caller sheds the resolution and the mark goes unsatisfied — oracle-safe).
// A nil semaphore (never constructed on the active path) is treated as unbounded.
func (r *trustMarkRequirement) acquireIssuerResolveSlot() bool {
	if r.issuerResolveSem == nil {
		return true
	}
	select {
	case r.issuerResolveSem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseIssuerResolveSlot returns a slot taken by acquireIssuerResolveSlot.
func (r *trustMarkRequirement) releaseIssuerResolveSlot() {
	if r.issuerResolveSem == nil {
		return
	}
	<-r.issuerResolveSem
}

// anchorAuthorizedTypes computes, from the matched anchor's validated
// trust_mark_issuers map, the set of REQUIRED types `iss` is authorized for.
// Per OpenID Federation 1.0 §3.1.2: for a given type, the array of issuer
// Entity IDs lists who may mint that type; an EMPTY array authorizes ANYONE.
// An ABSENT type entry authorizes NO one (the spec leaves this unspecified; the
// secure, fail-closed reading is "not authorized"). The set is restricted to
// r.requiredTypes (the only types that matter) so the cached entry directly
// answers every required type for a multi-type requirement.
func (r *trustMarkRequirement) anchorAuthorizedTypes(iss string, trustMarkIssuers map[string][]string) map[string]struct{} {
	out := make(map[string]struct{})
	if len(trustMarkIssuers) == 0 {
		return out
	}
	for _, reqType := range r.requiredTypes {
		allowed, present := trustMarkIssuers[reqType]
		if !present {
			// No entry for this type at this anchor ⇒ not authorized (fail-closed).
			continue
		}
		if len(allowed) == 0 {
			// Empty array ⇒ "anyone MAY issue" this type (spec §3.1.2).
			out[reqType] = struct{}{}
			continue
		}
		for _, e := range allowed {
			if e == iss {
				out[reqType] = struct{}{}
				break
			}
		}
	}
	return out
}

// issuerChainKeys returns the resolved issuer entity's chain-vouched signing
// keys (its validated Entity Configuration's own jwks) — the keys a Trust Mark
// it signs is verified against. Sourced from TrustChain.LeafKeys (the leaf
// config's signature was verified in ResolveTrustChain), NEVER a self-asserted
// set. nil/empty ⇒ the issuer published no usable entity keys (reject).
func issuerChainKeys(chain *TrustChain) []core.JWK {
	if chain == nil {
		return nil
	}
	return chain.LeafKeys
}

// authorizedIssuer returns the configured TrustMarkIssuer whose EntityID equals
// iss AND which is authorized for reqType (AllowedTypes empty ⇒ any type, else
// reqType must be listed). The FIRST match wins. Only an issuer matched here can
// satisfy a requirement via the CONFIGURED path.
func (r *trustMarkRequirement) authorizedIssuer(iss, reqType string) (TrustMarkIssuer, bool) {
	if iss == "" {
		return TrustMarkIssuer{}, false
	}
	for _, ti := range r.issuers {
		if ti.EntityID != iss {
			continue
		}
		if !typeAllowed(ti.AllowedTypes, reqType) {
			// This configured issuer exists but is NOT authorized for reqType —
			// keep scanning (a different configured entry for the same iss could
			// be authorized, though typically there is one).
			continue
		}
		return ti, true
	}
	return TrustMarkIssuer{}, false
}

// typeAllowed reports whether reqType is permitted by an issuer's AllowedTypes:
// an EMPTY list authorizes ANY type (broad trust), else the type MUST be listed.
func typeAllowed(allowedTypes []string, reqType string) bool {
	if len(allowedTypes) == 0 {
		return true
	}
	for _, t := range allowedTypes {
		if t == reqType {
			return true
		}
	}
	return false
}

// checkTrustMarkFresh enforces the §7 iat/exp window with the configured skew.
// iat is REQUIRED (a mark with no iat is rejected) and must not be in the future
// (now+skew >= iat); exp is OPTIONAL but, when present, must not be in the past
// (now-skew <= exp). The skew absorbs clock drift only.
func (r *trustMarkRequirement) checkTrustMarkFresh(claims trustMarkClaims, now time.Time) error {
	if claims.Iat <= 0 {
		return errors.New("trust mark has no iat")
	}
	iat := time.Unix(claims.Iat, 0)
	if now.Add(r.skew).Before(iat) {
		return fmt.Errorf("trust mark not yet valid (iat %d, now %d)", claims.Iat, now.Unix())
	}
	if claims.Exp > 0 {
		exp := time.Unix(claims.Exp, 0)
		if now.After(exp.Add(r.skew)) {
			return fmt.Errorf("trust mark expired at %d (now %d)", claims.Exp, now.Unix())
		}
	}
	return nil
}
