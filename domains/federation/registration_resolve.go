package federation

import (
	"context"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// On-the-fly federation resolution helpers for RegistrationClientStore, split
// out of registration.go so resolveFederationClient (the cache/lock/semaphore
// orchestration) and the resolution-proper (chain → trust marks → derive →
// cache) are each independently budgeted. Behavior is identical: every failure
// path negative-caches the id (short TTL) and yields the oracle-safe
// (nil,false) unknown-client outcome, the cause logged but never leaked.

// cachedClient returns the positive-cache hit for entityID if it is still fresh
// (lock-free read). It is consulted both before and (double-checked) after the
// per-entity resolve lock.
func (s *RegistrationClientStore) cachedClient(entityID string, now time.Time) (*core.Client, bool) {
	e, _ := s.cache.Load(entityID)
	if e == nil {
		return nil, false
	}
	entry, _ := e.(*federationClientEntry)
	if !entry.fresh(now) {
		return nil, false
	}
	return entry.client, true
}

// resolveAndDeriveClient runs the full resolution under the held per-entity lock
// + acquired concurrency slot: resolve the trust chain, apply the §7 trust-mark
// gate, derive the client, and cache it bounded by the chain exp. Any failure
// negative-caches the id (short TTL) and returns (nil,false) — the oracle-safe
// unknown-client outcome (the specific cause is logged, never leaked).
func (s *RegistrationClientStore) resolveAndDeriveClient(ctx context.Context, entityID string, now time.Time) (*core.Client, bool) {
	chain, err := s.resolver.ResolveTrustChain(ctx, entityID)
	if err != nil {
		// ResolveTrustChain already collapsed + logged the cause. SHORT-TTL
		// negative-cache so a repeated fake id doesn't re-fetch (it DELAYS, never
		// permanently pins — a legit RP whose superior recovered re-attempts soon).
		s.recordNegative(entityID, s.now())
		s.logError("federation: trust chain resolution failed for client", "client_id", entityID, "error", err)
		return nil, false
	}

	// §7 TRUST-MARK GATE (slice 4b): an EXTRA admission requirement AFTER the
	// chain validates and BEFORE the client is derived. nil/inert ⇒ no-op (slice-3
	// byte-identical). A missing/forged/unauthorized/expired/wrong-subject mark
	// fails CLOSED (the SAME oracle-safe unknown-client outcome). Negative-cache so
	// a repeated probe for an RP lacking the marks isn't re-resolved every request.
	if err := s.trustMarks.validate(ctx, chain.LeafEntityID, chain.LeafTrustMarks, s.now(), s.logError); err != nil {
		s.recordNegative(entityID, s.now())
		s.logError("federation: trust mark requirement unmet for client", "client_id", entityID, "error", err)
		return nil, false
	}

	client, err := MetadataToClient(entityID, chain.ResolvedRPMetadata, s.chainJWKS(chain), s.defaultTenantID)
	if err != nil {
		// Chain validated but metadata can't form a client — equally unusable;
		// negative-cache (short TTL) so it isn't re-resolved on every probe.
		s.recordNegative(entityID, s.now())
		s.logError("federation: derive client from resolved metadata failed", "client_id", entityID, "error", err)
		return nil, false
	}

	// A successful resolution clears any lingering negative entry (a legit RP that
	// just recovered from a transient superior outage); the positive cache below
	// is authoritative.
	s.clearNegative(entityID)

	// Cache bounded by the chain's earliest exp — never serve a client from an
	// expired chain. A non-positive/zero expiry (a validated chain never produces
	// one) is treated as already-expired: cache nothing, just return the derived
	// client for THIS request so a defensive zero doesn't pin a stale client.
	exp := chain.Expiry()
	if exp.After(now) {
		s.cache.Store(entityID, &federationClientEntry{client: client, expiresAt: exp})
	}
	return client, true
}
