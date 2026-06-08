package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
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

// resolvedIssuerEntry is one cached federation-resolution OUTCOME for a Trust
// Mark Issuer entity: the issuer's CHAIN-VALIDATED keys (sourced from its
// validated leaf Entity Configuration) and the set of trust-mark types the
// matched anchor's trust_mark_issuers authorizes it for. expiresAt is the
// issuer-chain's earliest exp (re-resolve past it). Immutable after publication.
type resolvedIssuerEntry struct {
	// keys are the issuer's chain-validated signing keys — the mark is verified
	// against THESE (vouched by the issuer's chain), never a self-asserted set.
	keys []core.JWK
	// authorizedTypes is the set of REQUIRED trust-mark types the matched anchor
	// authorizes this issuer for (per §3.1.2: listed in the anchor's
	// trust_mark_issuers for the type, OR the anchor's array for the type is
	// EMPTY ⇒ "anyone MAY issue"). Membership is the authorization answer; a type
	// absent from this set is NOT authorized for this issuer at this anchor. The
	// set spans every required type (not just the one that drove resolution) so
	// the cache answers a multi-type requirement without re-resolving.
	authorizedTypes map[string]struct{}
	// expiresAt bounds the entry by the issuer-chain's earliest exp.
	expiresAt time.Time
}

// fresh reports whether the entry is still within the issuer-chain's lifetime.
// nil-safe.
func (e *resolvedIssuerEntry) fresh(now time.Time) bool {
	return e != nil && now.Before(e.expiresAt)
}

// resolvedIssuerCache is a small bounded cache of federation-resolution
// outcomes keyed by issuer Entity ID. It mirrors the registration cache's
// shape (sync.Map for lock-free POSITIVE reads + a per-key resolve lock so a
// burst for one issuer resolves once) PLUS a short-TTL bounded NEGATIVE cache
// (a plain map + mutex, like the slice-3 registration negative cache) so a
// FAILED/slow issuer resolution is not retried on every distinct request.
//
// WHY the negative cache (slice 4c hardening): the positive cache alone holds
// only SUCCESSFUL resolutions, so a dead-or-slow iss is never memoized — an
// already-chained-but-malicious RP carrying many distinct-iss marks (or a
// repeated probe) would re-fire a full nested ResolveTrustChain(iss) every
// time, before the mark signature check. Memoizing the FAILURE (short TTL,
// bounded size) blunts that while the SHORT TTL re-attempts a legit issuer
// whose superior was transiently down (never permanently pinned).
type resolvedIssuerCache struct {
	m           sync.Map // issuerEntityID(string) -> *resolvedIssuerEntry
	resolveLock keyedMutex

	// negative (failed-resolution) cache: a plain map + mutex (writes only on
	// resolution FAILURE/shed; lookups sit on the miss/failure path, not the
	// positive hot path) so size accounting + oldest-eviction for the cap are
	// clean. negTTL/negMax bound it.
	negMu    sync.Mutex
	negCache map[string]time.Time // issuerEntityID -> negative-entry expiry
	negTTL   time.Duration
	negMax   int
}

func newResolvedIssuerCache(negTTL time.Duration, negMax int) *resolvedIssuerCache {
	return &resolvedIssuerCache{
		negCache: make(map[string]time.Time),
		negTTL:   negTTL,
		negMax:   negMax,
	}
}

// lookup returns a fresh cached entry for the issuer, or nil on miss/stale.
func (c *resolvedIssuerCache) lookup(issuerID string, now time.Time) *resolvedIssuerEntry {
	v, ok := c.m.Load(issuerID)
	if !ok {
		return nil
	}
	e, _ := v.(*resolvedIssuerEntry)
	if !e.fresh(now) {
		return nil
	}
	return e
}

// store publishes a positive entry for the issuer (and clears any stale
// negative entry — a just-resolved issuer is no longer dead).
func (c *resolvedIssuerCache) store(issuerID string, e *resolvedIssuerEntry) {
	c.m.Store(issuerID, e)
	c.clearNegative(issuerID)
}

// negativeHit reports whether issuerID has a FRESH negative entry (a recent
// failed/shed resolution within negTTL). A stale entry is lazily evicted.
func (c *resolvedIssuerCache) negativeHit(issuerID string, now time.Time) bool {
	if c.negTTL <= 0 {
		return false
	}
	c.negMu.Lock()
	defer c.negMu.Unlock()
	exp, ok := c.negCache[issuerID]
	if !ok {
		return false
	}
	if now.Before(exp) {
		return true
	}
	delete(c.negCache, issuerID)
	return false
}

// recordNegative remembers a FAILED/shed resolution for issuerID with a short
// TTL, enforcing the entry cap (sweep expired, then evict the soonest-to-expire)
// so the negative cache cannot itself become an unbounded-memory DoS.
func (c *resolvedIssuerCache) recordNegative(issuerID string, now time.Time) {
	if c.negTTL <= 0 {
		return
	}
	c.negMu.Lock()
	defer c.negMu.Unlock()
	if _, exists := c.negCache[issuerID]; !exists && c.negMax > 0 && len(c.negCache) >= c.negMax {
		c.evictNegativeLocked(now)
	}
	c.negCache[issuerID] = now.Add(c.negTTL)
}

// clearNegative drops any negative entry for issuerID.
func (c *resolvedIssuerCache) clearNegative(issuerID string) {
	c.negMu.Lock()
	delete(c.negCache, issuerID)
	c.negMu.Unlock()
}

// evictNegativeLocked makes room under the entry cap. Caller holds negMu. It
// sweeps every expired entry first (cheap, bounded — the map is capped); if
// that frees nothing (all still fresh under a sustained distinct-iss flood) it
// evicts the soonest-to-expire entry so a bounded amount of memory is reclaimed
// deterministically. Mirrors the slice-3 registration negative-cache eviction.
func (c *resolvedIssuerCache) evictNegativeLocked(now time.Time) {
	freed := false
	for k, exp := range c.negCache {
		if !now.Before(exp) {
			delete(c.negCache, k)
			freed = true
		}
	}
	if freed {
		return
	}
	var oldestKey string
	var oldestExp time.Time
	first := true
	for k, exp := range c.negCache {
		if first || exp.Before(oldestExp) {
			oldestKey, oldestExp, first = k, exp, false
		}
	}
	if !first {
		delete(c.negCache, oldestKey)
	}
}

// resolutionBudget is the per-validate-call DISTINCT-issuer resolution budget
// (slice 4c hardening). It is created ONCE per trust-mark validation (one RP
// registration) and threaded through satisfiedBy → validateMark →
// federationResolvedIssuerKeys so the cap spans every required type's scan, not
// just one. It bounds how many DISTINCT issuers this call will federation-
// RESOLVE: a malicious leaf carrying ~1500 distinct-iss marks would otherwise
// fire ~1500 full nested trust-chain resolutions. tryAcquire dedups (the same
// iss across N marks costs ONE slot) and fails closed once `max` distinct
// issuers have been granted — over-budget issuers do not resolve, so the
// required types they would have satisfied go unsatisfied (the RP stays
// unknown). Not safe for concurrent use; a single validate call is sequential.
type resolutionBudget struct {
	max     int                 // distinct-issuer cap (<=0 ⇒ unbounded; never constructed that way)
	granted map[string]struct{} // issuers already granted a resolution slot this call
}

// newResolutionBudget returns a budget capping distinct issuer resolutions at
// max. A non-positive max is treated as unbounded (defensive; the gate always
// passes a positive cap).
func newResolutionBudget(max int) *resolutionBudget {
	return &resolutionBudget{max: max, granted: make(map[string]struct{})}
}

// tryAcquire reserves a resolution slot for iss. It returns true when iss has
// ALREADY been granted this call (dedup — no new spend) or when a slot remains;
// false when iss is a NEW distinct issuer and the budget is exhausted. A
// non-positive max is unbounded. WHY dedup: two marks naming the same iss must
// cost one resolution, so the budget bounds DISTINCT issuers, not marks.
func (b *resolutionBudget) tryAcquire(iss string) bool {
	if b == nil {
		return true
	}
	if _, ok := b.granted[iss]; ok {
		return true
	}
	if b.max > 0 && len(b.granted) >= b.max {
		return false
	}
	b.granted[iss] = struct{}{}
	return true
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
	if compact == "" {
		return errors.New("empty trust mark")
	}
	// typ gate FIRST (before any signature work): a non-trust-mark+jwt token
	// signed by the issuer key (an id_token, an entity statement) must not be
	// accepted as a Trust Mark.
	typ, err := jwsHeaderTyp(compact)
	if err != nil {
		return fmt.Errorf("trust mark header: %w", err)
	}
	if typ != TrustMarkTyp {
		return fmt.Errorf("trust mark typ %q != %q", typ, TrustMarkTyp)
	}

	// Parse the UNVERIFIED payload only to read `iss` (to select the authorized
	// issuer + its verification keys). This grants no trust: if iss is forged to
	// name a configured/resolvable issuer, the signature check against that
	// issuer's REAL keys below fails (the attacker lacks the issuer's private
	// key). This is the same unverified-parse-to-navigate discipline the
	// trust-chain resolver uses.
	payload, err := unverifiedPayload(compact)
	if err != nil {
		return fmt.Errorf("trust mark payload: %w", err)
	}
	var claims trustMarkClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("trust mark claims: %w", err)
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
	if entry := r.resolvedIssuers.lookup(iss, now); entry != nil {
		if _, ok := entry.authorizedTypes[reqType]; !ok {
			return nil, fmt.Errorf("federation-resolved issuer %q not anchor-authorized for type %q", iss, reqType)
		}
		return entry.keys, nil
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
	if entry := r.resolvedIssuers.lookup(iss, now); entry != nil {
		if _, ok := entry.authorizedTypes[reqType]; !ok {
			return nil, fmt.Errorf("federation-resolved issuer %q not anchor-authorized for type %q", iss, reqType)
		}
		return entry.keys, nil
	}
	// Re-check the negative cache under the lock too: a sibling resolution for
	// THIS iss may have just recorded a failure while we waited.
	if r.resolvedIssuers.negativeHit(iss, now) {
		return nil, fmt.Errorf("federation-resolved issuer %q recently failed resolution (negative-cached)", iss)
	}

	// PER-CALL BUDGET (fix a): cap DISTINCT issuers this validate call will
	// resolve. Deduped — the same iss across N marks already short-circuits on the
	// cache above, but the budget bounds the DISTINCT-iss fan-out regardless. Over
	// budget ⇒ shed WITHOUT negative-caching (this is per-call load-shedding, not
	// an issuer failure; a legit issuer beyond budget in a flooded call resolves
	// on a later, smaller call). The required type goes unsatisfied → fail-closed.
	if !budget.tryAcquire(iss) {
		logError("federation: per-request issuer-resolution budget exhausted; shedding (unknown-client)",
			"issuer", iss, "trust_mark_type", reqType, "budget", r.maxResolvedIssuersPerRequest)
		return nil, fmt.Errorf("federation-resolved issuer %q: per-request resolution budget exhausted", iss)
	}

	// GLOBAL SEMAPHORE (fix b): bound CONCURRENT nested resolutions across ALL
	// in-flight registrations (independent of the slice-3 resolveSem, the OUTER RP
	// resolution). Non-blocking acquire; saturated ⇒ shed WITHOUT negative-caching
	// (load-shedding, not an issuer failure). Released on completion (defer).
	if !r.acquireIssuerResolveSlot() {
		logError("federation: nested issuer-resolution concurrency limit reached; shedding (unknown-client)",
			"issuer", iss, "trust_mark_type", reqType)
		return nil, fmt.Errorf("federation-resolved issuer %q: nested-resolution concurrency limit reached", iss)
	}
	defer r.releaseIssuerResolveSlot()

	// 1) Resolve the ISSUER's trust chain to a CONFIGURED anchor (slice 2,
	//    fail-closed). Failure = not a federation member / no configured anchor /
	//    forged chain → this issuer is not trusted → reject. NEGATIVE-cache the
	//    failure (short TTL) so a repeated/distinct-request dead-or-slow iss is
	//    not re-resolved every time (fix c); the short TTL re-attempts a legit
	//    issuer whose superior was transiently down.
	chain, err := r.resolver.ResolveTrustChain(ctx, iss)
	if err != nil {
		r.resolvedIssuers.recordNegative(iss, now)
		logError("federation: trust-mark issuer chain resolution failed", "issuer", iss, "trust_mark_type", reqType, "error", err)
		return nil, fmt.Errorf("federation-resolved issuer %q: chain resolution failed: %w", iss, err)
	}

	// 2) AUTHORIZATION ROOT: the matched ANCHOR's validated trust_mark_issuers
	//    MUST authorize iss for reqType. The map was read off the chain-validated
	//    ANCHOR config (the root of trust) in ResolveTrustChain — NOT a self-
	//    asserted value on the issuer/intermediate (the spec mandates the claim
	//    be IGNORED on any non-anchor). authorizedTypes captures EVERY required
	//    type this issuer is authorized for at this anchor so the cache answers
	//    multi-type requirements without re-resolving.
	authorizedTypes := r.anchorAuthorizedTypes(iss, chain.AnchorTrustMarkIssuers)
	if _, ok := authorizedTypes[reqType]; !ok {
		// The issuer chains to a configured anchor but that anchor does not
		// authorize it for reqType (not listed, or no trust_mark_issuers at all).
		// A genuine authorization MISS (the resolution succeeded but the issuer is
		// not authorized) — negative-cache it so a repeated probe doesn't re-resolve.
		r.resolvedIssuers.recordNegative(iss, now)
		logError("federation: anchor does not authorize trust-mark issuer for type",
			"issuer", iss, "anchor", chain.AnchorEntityID, "trust_mark_type", reqType)
		return nil, fmt.Errorf("federation-resolved issuer %q not anchor-authorized for type %q", iss, reqType)
	}

	// The issuer's CHAIN-VALIDATED keys (its leaf Entity Configuration jwks,
	// vouched by its chain) — verify the mark against THESE, never a self-
	// asserted set. The leaf config's signature was verified in validate(), so
	// the keys it carries are chain-vouched.
	keys := issuerChainKeys(chain)
	if len(keys) == 0 {
		// Resolved but unusable (no keys) — negative-cache so it isn't re-resolved
		// on every probe.
		r.resolvedIssuers.recordNegative(iss, now)
		logError("federation: resolved trust-mark issuer has no chain-validated keys", "issuer", iss)
		return nil, fmt.Errorf("federation-resolved issuer %q has no chain-validated keys", iss)
	}

	// Cache bounded by the issuer-chain's earliest exp — never verify against an
	// expired chain. A non-positive expiry (a validated chain never produces one)
	// is treated as already-expired: skip caching, just return the keys for THIS
	// mark so a defensive zero doesn't pin a stale resolution.
	exp := chain.Expiry()
	if exp.After(now) {
		r.resolvedIssuers.store(iss, &resolvedIssuerEntry{
			keys:            keys,
			authorizedTypes: authorizedTypes,
			expiresAt:       exp,
		})
	}
	return keys, nil
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
