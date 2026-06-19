package federation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
)

// OpenID Federation 1.0 §7 (Trust Marks) — an EXTRA admission requirement for
// automatic registration. A Trust Mark is a signed conformance assertion ("this
// RP is certified for X") minted by a Trust Mark Issuer. A federation operator
// can REQUIRE that an auto-registering RP carry a valid Trust Mark of each
// configured type, else the RP is not admitted — layered ON TOP of the slice-3
// trust-chain gate (slice 4b), additive (only STRICTER) and fail-closed.
//
// THE TRUST DECISION — what makes a required mark satisfied:
//
//   - An AUTHORIZED issuer must vouch for the mark. The PRIMARY (and, by
//     default, ONLY) authorization source is the operator-CONFIGURED
//     TrustMarkIssuer set: the mark's `iss` MUST match a configured issuer, that
//     issuer MUST be authorized for the type (AllowedTypes), and the mark's
//     signature MUST verify against the issuer's CONFIGURED keys (the operator
//     pins the keys). A mark from an unknown issuer, a known-but-unauthorized-
//     for-this-type issuer, or a forged/wrong-key signature does NOT satisfy via
//     this path.
//   - OPT-IN federation-resolved issuers (slice 4c, default-OFF). When
//     AllowFederationResolvedTrustMarkIssuers is set AND the iss is NOT
//     operator-configured, the issuer is treated as a DYNAMIC federation entity:
//     it is resolved via its trust chain to a CONFIGURED trust anchor (slice 2,
//     fail-closed) and MUST be listed in that anchor's validated
//     trust_mark_issuers for the required type; only then do the issuer's
//     CHAIN-VALIDATED keys verify the mark. The AUTHORIZATION ROOT is the
//     configured ANCHOR's trust_mark_issuers — NOT the issuer's self-assertion,
//     NOT the mark, NOT request input. An issuer not chaining to a configured
//     anchor, or not listed for the type, is REJECTED. Default-OFF leaves this
//     path entirely dormant (the configured path above is byte-identical, zero
//     regression to the reviewed gate). The configured path always takes
//     precedence (the resolved path is a fallback on its miss).
//   - `sub` MUST equal the RP (leaf) entity ID — the confused-deputy guard: a
//     genuine mark issued ABOUT entity A must NOT admit entity B. This is the
//     classic trust-mark binding; omitting it would let any federation member
//     present someone else's certification.
//   - The SIGNED `trust_mark_type` is AUTHORITATIVE (the unsigned wrapper entry
//     type is only a navigation hint): the mark satisfies a required type only
//     if the type CLAIM inside the signature-validated JWT equals it. A wrapper
//     that relabels a mark cannot launder it into a different type.
//   - typ == trust-mark+jwt (the §7 Trust Mark JOSE type) — so a plain
//     access/id token (or an entity statement) signed by the issuer key can
//     never be accepted as a Trust Mark.
//   - iat present + not in the future (bounded skew); exp (if present) not
//     expired (bounded skew) — a stale/future-dated mark is rejected.
//
// FAIL-CLOSED + ORACLE-SAFE: any missing / forged / unauthorized / expired /
// wrong-subject / wrong-type required mark returns an error; the registration
// gate maps that to the SAME slice-3 unknown-client path (the RP stays unknown,
// the specific cause to the log, never the wire — no trust-mark-specific wire
// signal). DEFAULT-OFF: an empty required-types set skips this entirely
// (byte-identical to the slice-3 path).

// TrustMarkTyp is the REQUIRED JOSE `typ` header of a §7 Trust Mark JWT. The
// gate asserts it BEFORE trusting any claim, so a token of another shape signed
// by the issuer's key (an id_token, an entity statement) cannot masquerade as a
// Trust Mark — mirroring the entity-statement+jwt typ discipline.
const TrustMarkTyp = "trust-mark+jwt"

// ErrTrustMarkRequirementUnmet is the single coarse error every trust-mark
// admission failure collapses into (a required type with no valid mark:
// missing, forged, unauthorized issuer, wrong subject, wrong signed type, or
// expired). Like ErrTrustChainInvalid it is oracle-reasonable: the registration
// gate maps it to the wrapped store's unknown-client miss, so the wire shape is
// byte-identical to any unknown client_id; the specific cause is logged.
var ErrTrustMarkRequirementUnmet = errors.New("federation: required trust mark not satisfied")

// trustMarkClaims is the payload of a §7 Trust Mark JWT. Only the members the
// gate validates are decoded; optional ref/logo_uri/delegation are ignored.
type trustMarkClaims struct {
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	TrustMarkType string `json:"trust_mark_type"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}

// trustMarkRequirement is the IMMUTABLE compiled trust-mark gate, derived from
// the federation Config once at construction and shared (read-only) across
// concurrent registrations. A nil *trustMarkRequirement (or one with no
// required types) is INERT — validate is a no-op, so the slice-3 path stays
// byte-identical (the default-off posture).
type trustMarkRequirement struct {
	// requiredTypes are the Trust Mark Type URIs an RP MUST each satisfy. Empty
	// ⇒ inert.
	requiredTypes []string
	// issuers are the operator-CONFIGURED authorized Trust Mark Issuers — the
	// PRIMARY (and, by default, only) issuers whose signed marks can satisfy a
	// requirement.
	issuers []TrustMarkIssuer
	// allowedAlgs is the asymmetric signing-alg allowlist passed to
	// security.VerifyCompactJWS (a federation/trust-mark signing key is
	// asymmetric; the verifier refuses any symmetric alg or alg=none regardless).
	allowedAlgs map[string]struct{}
	// skew widens the iat/exp freshness window (clock drift between this server
	// and the Trust Mark Issuer).
	skew time.Duration

	// ----- federation-resolved issuer path (slice 4c, opt-in) -----------------

	// allowFederationResolved opts into the DYNAMIC-FEDERATION issuer path: when
	// true, a required mark whose iss is NOT operator-configured may still be
	// satisfied by resolving the issuer as a federation entity. Default false ⇒
	// the configured path above is the ONLY one (byte-identical to slice 4b).
	allowFederationResolved bool
	// resolver resolves a candidate issuer's trust chain to a CONFIGURED trust
	// anchor (slice 2, fail-closed). Used ONLY on the federation-resolved path.
	// nil / inert ⇒ the path is dormant regardless of the flag (no anchor = no
	// root of trust = nothing to authorize against).
	resolver *TrustChainResolver
	// resolvedIssuers caches the OUTCOME of resolving an issuer as a federation
	// entity (its chain-validated keys + the per-type authorization read off the
	// anchor's trust_mark_issuers), bounded by the issuer-chain exp so a mark is
	// never validated against an expired chain. WHY a dedicated cache: the
	// resolution is a multi-fetch trust-chain walk; without it, EVERY presented
	// mark from a resolved issuer would re-resolve. It also holds a SHORT-TTL
	// NEGATIVE cache so a FAILED/slow issuer resolution is not retried on every
	// request (the positive cache alone never memoizes a dead iss → an attacker's
	// distinct-iss marks would each re-resolve). Concurrency-safe.
	resolvedIssuers *resolvedIssuerCache

	// ----- federation-resolved issuer DoS bounds (slice 4c hardening) ---------
	//
	// The nested issuer resolution is a NEW outbound trigger fired BEFORE the
	// mark signature check; an already-chained-but-malicious RP can carry ~1500
	// distinct-iss marks, each a full ~chain-depth nested resolution. These bound
	// the per-call fan-out, the GLOBAL concurrency, and re-resolution of dead
	// issuers. All fail-CLOSED + oracle-safe (an unresolvable/shed issuer simply
	// does not satisfy a required type). Only the federation-resolved path
	// touches them; default-off leaves them dormant.

	// maxResolvedIssuersPerRequest caps DISTINCT issuer resolutions per validate
	// call (deduped). Beyond it, further distinct-iss resolutions are not
	// attempted (fail-closed). Bounds the per-RP fan-out regardless of how many
	// distinct-iss marks the leaf carries.
	maxResolvedIssuersPerRequest int
	// issuerResolveSem is the GLOBAL counting semaphore (a buffered channel)
	// bounding CONCURRENT nested issuer resolutions across ALL in-flight
	// registrations — independent of the slice-3 resolveSem (the OUTER RP
	// resolution, already consumed by the time the trust-mark gate runs).
	// Non-blocking acquire, fail-closed when saturated. nil ⇒ unbounded
	// (defensive; constructor always sets it on the resolved path).
	issuerResolveSem chan struct{}
	// maxLeafTrustMarks caps a validated leaf's trust_marks entries before the
	// scan is bounded (defense-in-depth against an absurd-cardinality leaf).
	maxLeafTrustMarks int
}

// newTrustMarkRequirement compiles the trust-mark gate from a Config. Returns
// nil when the gate is OFF (nil cfg or no RequiredTrustMarkTypes), so callers
// can nil-check for the byte-identical default-off path. The alg allowlist
// mirrors the trust-chain resolver's (the full asymmetric set;
// VerifyCompactJWS refuses symmetric/none regardless).
//
// resolver is the slice-2 trust-chain resolver, supplied by the registration
// store so the federation-resolved issuer path (slice 4c) can discover an
// issuer entity. It is wired ONLY when AllowFederationResolvedTrustMarkIssuers
// is set AND the resolver is non-nil + anchor-enabled; otherwise that path is
// dormant and the gate behaves byte-identically to slice 4b (configured issuers
// only). A nil resolver with the flag set leaves the federation path off (no
// root of trust to authorize against).
func newTrustMarkRequirement(cfg *Config, resolver *TrustChainResolver) *trustMarkRequirement {
	if cfg == nil || len(cfg.RequiredTrustMarkTypes) == 0 {
		return nil
	}
	r := &trustMarkRequirement{
		requiredTypes:     append([]string(nil), cfg.RequiredTrustMarkTypes...),
		issuers:           cfg.TrustMarkIssuers,
		allowedAlgs:       federationAsymmetricAlgs(),
		skew:              cfg.maxClockSkew(),
		maxLeafTrustMarks: cfg.maxLeafTrustMarks(),
	}
	// Federation-resolved issuer path is OPT-IN and needs a live resolver (a
	// configured trust anchor is the root of trust the issuer's chain must reach
	// AND whose trust_mark_issuers authorizes it). Absent the flag or a usable
	// resolver the path stays dormant — the gate is byte-identical to slice 4b
	// (the DoS bounds below are constructed ONLY here, so a default-off build
	// allocates none of them).
	if cfg.AllowFederationResolvedTrustMarkIssuers && resolver != nil && resolver.Enabled() {
		r.allowFederationResolved = true
		r.resolver = resolver
		r.resolvedIssuers = newResolvedIssuerCache(
			cfg.resolvedIssuerNegativeCacheTTL(), cfg.resolvedIssuerNegativeCacheMaxSize())
		r.maxResolvedIssuersPerRequest = cfg.maxResolvedIssuersPerRequest()
		r.issuerResolveSem = make(chan struct{}, cfg.maxConcurrentIssuerResolutions())
	}
	return r
}

// enabled reports whether the gate is live (at least one required type). A nil
// receiver is inert.
func (r *trustMarkRequirement) enabled() bool {
	return r != nil && len(r.requiredTypes) > 0
}

// validate enforces the §7 requirement: for EACH required type the leaf MUST
// carry at least one mark that fully validates (authorized issuer + signature +
// sub==leaf + signed-type==required + typ + fresh). The authorized-issuer check
// is the operator-CONFIGURED set first, then — only when opted in — the
// federation-resolved path. Returns nil when every required type is satisfied,
// else ErrTrustMarkRequirementUnmet (fail-closed; the specific cause goes to
// logError, never the caller). A nil/inert receiver returns nil (no requirement)
// so the slice-3 path is unchanged.
//
// ctx is threaded through to the federation-resolved issuer path (it may run a
// trust-chain resolution for a candidate issuer); on the configured-only path
// it is unused.
//
// now is injected (not time.Now) so a test drives a fixed instant through both
// the minted mark's iat/exp AND this check — no real-clock date bomb.
func (r *trustMarkRequirement) validate(ctx context.Context, leafEntityID string, marks []TrustMarkEntry, now time.Time, logError func(msg string, args ...any)) error {
	if !r.enabled() {
		return nil
	}
	if logError == nil {
		logError = func(string, ...any) {}
	}
	// Defense-in-depth: an absurd-cardinality leaf (the 256KiB cap permits ~1500
	// trust_marks entries) is rejected CLOSED before any per-type scan — a
	// malicious already-chained RP cannot force a thousands-deep scan + nested
	// resolution fan-out. A legitimate RP carries a handful of marks, far under
	// the cap. Oracle-safe (the RP stays unknown, the same as any unsatisfied
	// requirement).
	if r.maxLeafTrustMarks > 0 && len(marks) > r.maxLeafTrustMarks {
		logError("federation: leaf trust_marks count exceeds cap; rejecting",
			"leaf", leafEntityID, "count", len(marks), "cap", r.maxLeafTrustMarks)
		return fmt.Errorf("%w: leaf carries %d trust marks (cap %d)", ErrTrustMarkRequirementUnmet, len(marks), r.maxLeafTrustMarks)
	}
	// One PER-CALL distinct-issuer resolution budget spans EVERY required type's
	// scan (a malicious leaf could otherwise spread distinct-iss marks across
	// types to multiply the fan-out). Deduped + capped. On the configured-only
	// path (the budget is never consulted) this allocates a tiny map and is
	// untouched.
	budget := newResolutionBudget(r.maxResolvedIssuersPerRequest)
	for _, reqType := range r.requiredTypes {
		if !r.satisfiedBy(ctx, leafEntityID, reqType, marks, now, budget, logError) {
			// One unmet required type fails the whole admission (fail-closed). The
			// per-candidate cause was already logged inside satisfiedBy.
			logError("federation: required trust mark not satisfied", "leaf", leafEntityID, "trust_mark_type", reqType)
			return fmt.Errorf("%w: type %q", ErrTrustMarkRequirementUnmet, reqType)
		}
	}
	return nil
}

// satisfiedBy reports whether ANY of the leaf's trust_marks entries is a VALID
// mark for reqType. It iterates EVERY entry and fully validates each (the
// unsigned wrapper type is NOT used as a gate — only as a cheap pre-filter
// skip; the authoritative match is the SIGNED type == reqType inside
// validateMark). So a correctly-signed mark satisfies even if its wrapper type
// is mislabeled, and a wrapper that merely CLAIMS reqType over a different
// signed type does NOT satisfy (the signed type is authoritative).
func (r *trustMarkRequirement) satisfiedBy(ctx context.Context, leafEntityID, reqType string, marks []TrustMarkEntry, now time.Time, budget *resolutionBudget, logError func(msg string, args ...any)) bool {
	for i := range marks {
		if err := r.validateMark(ctx, leafEntityID, reqType, marks[i].TrustMark, now, budget, logError); err != nil {
			// Not a valid mark FOR THIS TYPE (wrong type, wrong subject, forged,
			// unauthorized issuer, expired, ...). Log + keep looking — another
			// entry may satisfy this type.
			logError("federation: trust mark candidate rejected", "leaf", leafEntityID, "trust_mark_type", reqType, "error", err)
			continue
		}
		return true
	}
	return false
}

// validateMark fully validates a single compact Trust Mark JWS as satisfying
// reqType for leafEntityID. The order is security-deliberate: cheap structural
// + typ checks, then resolve the AUTHORIZED issuer's verification keys by the
// (unverified) iss — FIRST the operator-configured set, then (opt-in) the
// federation-resolved path — then VERIFY THE SIGNATURE against those keys (the
// trust gate), and only AFTER the signature holds do the claim bindings (sub,
// signed type, freshness) — so every trusted claim comes from a signature-
// validated mark. Returns nil only when the mark is a valid, authorized, fresh,
// correctly-bound mark of reqType.
func (r *trustMarkRequirement) validateMark(ctx context.Context, leafEntityID, reqType, compact string, now time.Time, budget *resolutionBudget, logError func(msg string, args ...any)) error {
	// Cheap structural gate: typ == trust-mark+jwt + the (unverified) claims,
	// parsed only to read `iss` (to select the authorized issuer). This grants no
	// trust — the signature against the issuer's REAL keys below is the gate.
	claims, err := parseTrustMark(compact)
	if err != nil {
		return err
	}

	// Resolve the AUTHORIZED issuer's verification keys for reqType. The
	// CONFIGURED path is PRIMARY: a configured TrustMarkIssuer whose EntityID
	// equals iss AND whose AllowedTypes permits reqType. (The AllowedTypes check
	// is on reqType, which validateMark also pins to the SIGNED type below, so an
	// issuer cannot be tricked via a relabeled wrapper.)
	verifyKeys, err := r.resolveIssuerKeys(ctx, claims.Iss, reqType, now, budget, logError)
	if err != nil {
		return err
	}

	// SIGNATURE — the trust gate. Verify against the resolved keys via the shared
	// asymmetric verifier (alg=none/symmetric-safe, kid-bound). A forged or
	// wrong-key signature fails here. The SAME verifier + alg allowlist whether
	// the keys came from the configured set or a validated federation chain.
	if _, err := security.VerifyCompactJWS(compact, verifyKeys, r.allowedAlgs); err != nil {
		return fmt.Errorf("trust mark signature: %w", err)
	}

	// Claim bindings — now trusted (the signature held). IDENTICAL on both the
	// configured and the federation-resolved path (the slice-4b invariants apply
	// regardless of how the issuer was authorized).
	return r.checkMarkBindings(claims, leafEntityID, reqType, now)
}

// resolveIssuerKeys returns the verification keys of the issuer authorized to
// satisfy reqType for the given iss, or an error when no authorized issuer
// vouches for this iss+type. It is the AUTHORIZATION decision: the configured
// path is tried FIRST (operator-pinned keys, primary), and ONLY on its miss —
// when opted in — the federation-resolved path (the issuer discovered via its
// trust chain to a configured anchor that lists it for reqType). The returned
// keys are then used to verify the mark's signature by the caller.
func (r *trustMarkRequirement) resolveIssuerKeys(ctx context.Context, iss, reqType string, now time.Time, budget *resolutionBudget, logError func(msg string, args ...any)) ([]core.JWK, error) {
	// PRIMARY: operator-configured authorized issuer. This path NEVER consults
	// the per-call resolution budget / semaphore / negative cache — it runs no
	// nested resolution (operator-pinned keys), so a configured-issuer mark is
	// unaffected by the DoS bounds.
	if issuer, ok := r.authorizedIssuer(iss, reqType); ok {
		if len(issuer.Keys) == 0 {
			return nil, fmt.Errorf("authorized issuer %q has no configured keys", issuer.EntityID)
		}
		return issuer.Keys, nil
	}

	// FALLBACK (opt-in, default-off): the iss is not operator-configured. Try the
	// federation-resolved path — discover the issuer as a federation entity and
	// require the configured anchor to authorize it for reqType. Default-off ⇒
	// this branch never runs (the gate is byte-identical to slice 4b).
	if r.allowFederationResolved {
		keys, err := r.federationResolvedIssuerKeys(ctx, iss, reqType, now, budget, logError)
		if err == nil {
			return keys, nil
		}
		// The specific federation-resolution failure (not a member / no
		// configured anchor / anchor doesn't authorize the type / chain forged)
		// is logged inside federationResolvedIssuerKeys; collapse to the same
		// not-authorized error shape as the configured-miss below (oracle-safe).
	}

	return nil, fmt.Errorf("trust mark issuer %q not authorized for type %q", iss, reqType)
}

// federationResolvedIssuerKeys implements the slice-4c DYNAMIC-FEDERATION
// issuer path: for an iss NOT operator-configured, discover it as a federation
// entity and return its CHAIN-VALIDATED keys IFF the configured anchor it
// chains to authorizes it for reqType. A resolved issuer is admitted ONLY when
// BOTH hold:
//
//  1. ResolveTrustChain(iss) reaches a CONFIGURED trust anchor (slice 2,
//     fail-closed) — i.e. iss is a real federation member rooted in operator
//     trust; AND
//  2. that ANCHOR's validated trust_mark_issuers lists iss as authorized for
//     reqType (the authorization ROOT is the anchor — the root of trust — not
//     the issuer, the mark, or request input). Per spec an EMPTY array for the
//     type authorizes anyone; an ABSENT entry authorizes no one (fail-closed
//     interpretation of the spec's unspecified case).
//
// Only then are the issuer's chain-validated keys returned to verify the mark.
// The outcome (keys + per-type authorization) is cached bounded by the issuer-
// chain exp so repeated marks from a resolved issuer don't re-resolve. Any
// failure returns an error (the caller collapses it to not-authorized;
// oracle-safe — the RP stays unknown).
//
// DoS bounds (slice 4c hardening), gating the nested ResolveTrustChain — a NEW
// outbound trigger fired BEFORE the mark signature check — so an already-chained
// but malicious RP carrying many distinct-iss marks cannot amplify one
// registration into an unbounded nested-resolution flood:
//
//   - NEGATIVE cache: a recently-FAILED resolution for iss is not retried (the
//     positive cache alone never memoizes a dead/slow iss).
//   - per-call BUDGET: caps DISTINCT issuers resolved this validate call
//     (deduped); over-budget issuers are not resolved (fail-closed).
//   - global SEMAPHORE: caps CONCURRENT nested resolutions across all
//     registrations; saturated ⇒ shed (fail-closed), independent of the slice-3
//     outer-resolution semaphore.
//
// budget-exceeded + semaphore-saturated are LOAD-SHEDDING (not an issuer
// failure), so they do NOT poison the negative cache — a legit issuer must not
// be pinned out by a transient flood; it re-attempts on a later, unsaturated
// call. A genuine resolution FAILURE (no chain / no anchor-auth / no keys) IS
// negative-cached.
func (r *trustMarkRequirement) federationResolvedIssuerKeys(ctx context.Context, iss, reqType string, now time.Time, budget *resolutionBudget, logError func(msg string, args ...any)) ([]core.JWK, error) {
	if logError == nil {
		logError = func(string, ...any) {}
	}
	if r.resolver == nil || !r.resolver.Enabled() || r.resolvedIssuers == nil {
		return nil, errors.New("federation-resolved issuer path not active")
	}

	// Cache HIT: a fresh prior resolution of this issuer. The cached entry holds
	// the issuer's chain-validated keys + the types the anchor authorized it for;
	// authorize reqType against that set without re-resolving (and without
	// spending the budget/semaphore — no resolution happens).
	if keys, found, err := r.cachedResolvedKeys(iss, reqType, now); found {
		return keys, err
	}

	// NEGATIVE-cache check BEFORE the per-issuer lock or any resolution: a
	// recently-failed iss must not re-trigger a nested resolution (the cheap
	// defense against a distinct-iss-mark flood / repeated probe). Oracle-safe
	// (the same not-resolved error as any miss). Spends NO budget/semaphore.
	if r.resolvedIssuers.negativeHit(iss, now) {
		return nil, fmt.Errorf("federation-resolved issuer %q recently failed resolution (negative-cached)", iss)
	}

	// Cache MISS: resolve under a per-issuer lock so a burst of marks from the
	// same issuer resolves the chain ONCE.
	unlock := r.resolvedIssuers.resolveLock.lock(iss)
	defer unlock()
	// Double-checked: another goroutine may have populated it while we waited.
	if keys, found, err := r.cachedResolvedKeys(iss, reqType, now); found {
		return keys, err
	}
	// Re-check the negative cache under the lock too: a sibling resolution for
	// THIS iss may have just recorded a failure while we waited.
	if r.resolvedIssuers.negativeHit(iss, now) {
		return nil, fmt.Errorf("federation-resolved issuer %q recently failed resolution (negative-cached)", iss)
	}

	// PER-CALL BUDGET + GLOBAL SEMAPHORE: bound the nested-resolution fan-out
	// (per-call distinct issuers) + concurrency (across all registrations). Both
	// shed WITHOUT negative-caching (load-shedding, not an issuer failure).
	if err := r.acquireResolutionSlots(iss, reqType, budget, logError); err != nil {
		return nil, err
	}
	defer r.releaseIssuerResolveSlot()

	return r.resolveAndAuthorizeIssuer(ctx, iss, reqType, now, logError)
}
