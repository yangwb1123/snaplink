package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// Federation-resolved trust-mark issuer helpers (OpenID Federation 1.0 §7 +
// slice 4c), split out of trust_marks.go so federationResolvedIssuerKeys (the
// cache/lock/budget/semaphore orchestration) and its constituent steps (cache
// authorization, slot acquisition, the nested resolution-proper) are each
// independently budgeted. Behavior is identical: all paths are fail-CLOSED +
// oracle-safe, load-shedding never poisons the negative cache, and every genuine
// resolution FAILURE is negative-cached (short TTL). parseTrustMark lives here
// too (the cheap structural gate validateMark runs first).

// parseTrustMark runs the cheap structural gate on a compact Trust Mark JWS
// (non-empty + typ == trust-mark+jwt) and decodes its UNVERIFIED payload into
// trustMarkClaims. The typ gate is FIRST (before any signature work) so a
// non-trust-mark+jwt token signed by the issuer key (an id_token, an entity
// statement) cannot be accepted as a Trust Mark. The claims are parsed only to
// read `iss` (to select the authorized issuer + keys); this grants no trust —
// the signature check against the issuer's REAL keys (in validateMark) is the
// gate. A forged iss naming a configured/resolvable issuer fails that check
// (the attacker lacks the issuer's private key). Same unverified-parse-to-
// navigate discipline the trust-chain resolver uses.
func parseTrustMark(compact string) (trustMarkClaims, error) {
	if compact == "" {
		return trustMarkClaims{}, errors.New("empty trust mark")
	}
	typ, err := jwsHeaderTyp(compact)
	if err != nil {
		return trustMarkClaims{}, fmt.Errorf("trust mark header: %w", err)
	}
	if typ != TrustMarkTyp {
		return trustMarkClaims{}, fmt.Errorf("trust mark typ %q != %q", typ, TrustMarkTyp)
	}
	payload, err := unverifiedPayload(compact)
	if err != nil {
		return trustMarkClaims{}, fmt.Errorf("trust mark payload: %w", err)
	}
	var claims trustMarkClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return trustMarkClaims{}, fmt.Errorf("trust mark claims: %w", err)
	}
	return claims, nil
}

// cachedResolvedKeys answers from the positive cache: a fresh prior resolution
// of iss. found=false ⇒ no fresh entry (the caller proceeds to resolve). When
// found, err authorizes reqType against the cached anchor-authorized set (nil
// keys + an error when the cached issuer is not authorized for reqType).
func (r *trustMarkRequirement) cachedResolvedKeys(iss, reqType string, now time.Time) ([]core.JWK, bool, error) {
	entry := r.resolvedIssuers.lookup(iss, now)
	if entry == nil {
		return nil, false, nil
	}
	if _, ok := entry.authorizedTypes[reqType]; !ok {
		return nil, true, fmt.Errorf("federation-resolved issuer %q not anchor-authorized for type %q", iss, reqType)
	}
	return entry.keys, true, nil
}

// acquireResolutionSlots takes the per-call distinct-issuer budget slot (fix a)
// then the global concurrency semaphore (fix b) before a nested resolution. A
// non-nil error means the resolution was SHED (budget exhausted or semaphore
// saturated) — load-shedding, NOT negative-cached, so a legit issuer re-attempts
// on a later, smaller/unsaturated call. On success the caller MUST defer
// releaseIssuerResolveSlot.
func (r *trustMarkRequirement) acquireResolutionSlots(iss, reqType string, budget *resolutionBudget, logError func(msg string, args ...any)) error {
	// PER-CALL BUDGET (fix a): cap DISTINCT issuers this validate call will
	// resolve. Deduped — the same iss across N marks already short-circuits on the
	// cache above, but the budget bounds the DISTINCT-iss fan-out regardless. Over
	// budget ⇒ shed WITHOUT negative-caching (this is per-call load-shedding, not
	// an issuer failure; a legit issuer beyond budget in a flooded call resolves
	// on a later, smaller call). The required type goes unsatisfied → fail-closed.
	if !budget.tryAcquire(iss) {
		logError("federation: per-request issuer-resolution budget exhausted; shedding (unknown-client)",
			"issuer", iss, "trust_mark_type", reqType, "budget", r.maxResolvedIssuersPerRequest)
		return fmt.Errorf("federation-resolved issuer %q: per-request resolution budget exhausted", iss)
	}

	// GLOBAL SEMAPHORE (fix b): bound CONCURRENT nested resolutions across ALL
	// in-flight registrations (independent of the slice-3 resolveSem, the OUTER RP
	// resolution). Non-blocking acquire; saturated ⇒ shed WITHOUT negative-caching
	// (load-shedding, not an issuer failure). Released on completion (defer).
	if !r.acquireIssuerResolveSlot() {
		logError("federation: nested issuer-resolution concurrency limit reached; shedding (unknown-client)",
			"issuer", iss, "trust_mark_type", reqType)
		return fmt.Errorf("federation-resolved issuer %q: nested-resolution concurrency limit reached", iss)
	}
	return nil
}

// resolveAndAuthorizeIssuer runs the nested trust-chain resolution for iss (held
// under the per-issuer lock + acquired slots), authorizes it against the matched
// anchor's trust_mark_issuers, extracts its chain-validated keys, and caches the
// outcome bounded by the issuer-chain exp. Every genuine failure (no chain / not
// anchor-authorized / no keys) negative-caches iss (fix c) and returns an error.
func (r *trustMarkRequirement) resolveAndAuthorizeIssuer(ctx context.Context, iss, reqType string, now time.Time, logError func(msg string, args ...any)) ([]core.JWK, error) {
	// 1) Resolve the ISSUER's trust chain to a CONFIGURED anchor (slice 2,
	//    fail-closed). Any failure negative-caches iss (fix c) so a dead/slow iss
	//    is not re-resolved every time (the short TTL re-attempts a legit issuer).
	chain, err := r.resolver.ResolveTrustChain(ctx, iss)
	if err != nil {
		r.resolvedIssuers.recordNegative(iss, now)
		logError("federation: trust-mark issuer chain resolution failed", "issuer", iss, "trust_mark_type", reqType, "error", err)
		return nil, fmt.Errorf("federation-resolved issuer %q: chain resolution failed: %w", iss, err)
	}

	// 2) AUTHORIZATION ROOT: the matched ANCHOR's validated trust_mark_issuers
	//    MUST authorize iss for reqType (read off the chain-validated anchor — the
	//    root of trust — never a self-asserted value; the spec IGNORES it on any
	//    non-anchor). authorizedTypes spans every required type so the cache
	//    answers a multi-type requirement without re-resolving.
	authorizedTypes := r.anchorAuthorizedTypes(iss, chain.AnchorTrustMarkIssuers)
	if _, ok := authorizedTypes[reqType]; !ok {
		// Chains to a configured anchor but that anchor does not authorize this
		// type — a genuine MISS; negative-cache so a repeated probe doesn't re-resolve.
		r.resolvedIssuers.recordNegative(iss, now)
		logError("federation: anchor does not authorize trust-mark issuer for type",
			"issuer", iss, "anchor", chain.AnchorEntityID, "trust_mark_type", reqType)
		return nil, fmt.Errorf("federation-resolved issuer %q not anchor-authorized for type %q", iss, reqType)
	}

	// The issuer's CHAIN-VALIDATED keys (its leaf config jwks, vouched by its
	// chain) — verify the mark against THESE, never a self-asserted set.
	keys := issuerChainKeys(chain)
	if len(keys) == 0 {
		// Resolved but unusable (no keys) — negative-cache so it isn't re-resolved.
		r.resolvedIssuers.recordNegative(iss, now)
		logError("federation: resolved trust-mark issuer has no chain-validated keys", "issuer", iss)
		return nil, fmt.Errorf("federation-resolved issuer %q has no chain-validated keys", iss)
	}

	r.cacheResolvedIssuer(iss, keys, authorizedTypes, chain.Expiry(), now)
	return keys, nil
}

// cacheResolvedIssuer publishes a successful resolution bounded by the issuer-
// chain's earliest exp — never verify against an expired chain. A non-positive
// expiry (a validated chain never produces one) is treated as already-expired:
// skip caching, so a defensive zero doesn't pin a stale resolution.
func (r *trustMarkRequirement) cacheResolvedIssuer(iss string, keys []core.JWK, authorizedTypes map[string]struct{}, exp, now time.Time) {
	if !exp.After(now) {
		return
	}
	r.resolvedIssuers.store(iss, &resolvedIssuerEntry{
		keys:            keys,
		authorizedTypes: authorizedTypes,
		expiresAt:       exp,
	})
}
