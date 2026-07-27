package federation

import (
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

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
