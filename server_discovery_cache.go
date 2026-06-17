package sso

import (
	"context"
	"sort"
	"time"

	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/oidc"
)

func WithDiscoveryCacheTTL(d time.Duration) Option {
	return func(s *Server) { s.discoveryCacheTTL = d }
}

// discoverySnapshot returns the current client-store-derived snapshot,
// refreshing it via single-flight when stale or absent. Safe for
// concurrent use. When the client store is unavailable or returns
// an error, the snapshot has empty/false fields (the legacy
// "degraded discovery" behavior) — discovery MUST keep serving even
// when the store is sick.
func (s *Server) discoverySnapshot(ctx context.Context) *clientDiscoverySnapshot {
	ttl := s.discoveryCacheTTL
	if ttl == 0 {
		// Caching disabled — compute every time. The single-flight
		// path is bypassed so dev-loop hot-reload sees DCR edits
		// instantly.
		return s.computeDiscoverySnapshot(ctx)
	}
	if snap := s.discoveryCache.Load(); snap != nil && time.Now().Before(snap.expiresAt) {
		return snap
	}
	s.discoveryCacheMu.Lock()
	defer s.discoveryCacheMu.Unlock()
	// Re-check after acquiring the lock — a peer may have refreshed
	// while we waited. Standard double-checked-locking pattern.
	if snap := s.discoveryCache.Load(); snap != nil && time.Now().Before(snap.expiresAt) {
		return snap
	}
	// Stale-but-present snapshot: before paying for a full List +
	// re-projection, ask the store for a cheap fingerprint. If the
	// client set hasn't changed in any discovery-relevant way, reuse
	// the prior snapshot's derived fields and just extend the TTL.
	if prev := s.discoveryCache.Load(); prev != nil && prev.fpValid {
		if snap := s.refreshIfUnchanged(ctx, prev); snap != nil {
			s.discoveryCache.Store(snap)
			return snap
		}
	}
	snap := s.computeDiscoverySnapshot(ctx)
	s.discoveryCache.Store(snap)
	return snap
}

// refreshIfUnchanged returns a TTL-extended copy of prev when the
// client store exposes a cheap fingerprint (core.ClientStoreStats) that
// still matches prev's. The returned snapshot shares prev's derived
// fields verbatim — they were computed from the same client set and the
// slices are immutable after publication, so sharing is race-free. It
// returns nil to signal "fingerprint changed, unavailable, or
// unsupported — fall back to a full recompute".
func (s *Server) refreshIfUnchanged(ctx context.Context, prev *clientDiscoverySnapshot) *clientDiscoverySnapshot {
	stats, ok := s.clientStore.(core.ClientStoreStats)
	if !ok {
		return nil
	}
	count, hash, err := stats.Stats(ctx)
	if err != nil {
		// Treat a Stats outage like the degraded-discovery path: don't
		// trust a possibly-partial fingerprint, force a recompute (which
		// itself degrades gracefully when List fails).
		return nil
	}
	if count != prev.fpCount || hash != prev.fpHash {
		return nil
	}
	refreshed := *prev
	refreshed.expiresAt = time.Now().Add(s.discoveryCacheTTL)
	return &refreshed
}

// computeDiscoverySnapshot does the expensive client-store iteration
// once and projects all four derived fields. Splitting compute from
// the cache wrapper lets tests assert the projection directly
// without poking the cache.
//
// When the store exposes a cheap fingerprint (core.ClientStoreStats),
// the snapshot is stamped with that fingerprint computed from the SAME
// clients we just Listed (no second store round-trip). The stamp must
// match what Stats() would independently return for this set, so the
// next miss can compare cheaply and skip the recompute — see
// refreshIfUnchanged. core.ClientSetFingerprint reads only the
// discovery-relevant fields, so a backend whose schema omits some of
// them (sqlite) digests List() and Stats() identically (both zero).
func (s *Server) computeDiscoverySnapshot(ctx context.Context) *clientDiscoverySnapshot {
	snap := &clientDiscoverySnapshot{expiresAt: time.Now().Add(s.discoveryCacheTTL)}
	if s.idTokenIssuer != nil {
		snap.scopes = []string{ScopeOpenID}
	}
	if s.clientStore == nil {
		return snap
	}
	clients, err := s.clientStore.List(ctx)
	if err != nil {
		return snap
	}
	// Stamp the fingerprint only when the cache is live (ttl > 0): with
	// caching disabled the snapshot is discarded immediately, so the
	// digest would be pure waste on every request.
	if s.discoveryCacheTTL > 0 {
		if _, ok := s.clientStore.(core.ClientStoreStats); ok {
			snap.fpValid = true
			snap.fpCount = len(clients)
			snap.fpHash = core.ClientSetFingerprint(clients)
		}
	}
	scopesSeen := map[string]struct{}{}
	if s.idTokenIssuer != nil {
		scopesSeen[ScopeOpenID] = struct{}{}
	}
	adTypesSeen := map[string]struct{}{}
	allRequireSignedRequestObject := len(clients) > 0
	for _, c := range clients {
		if c == nil {
			allRequireSignedRequestObject = false
			continue
		}
		if c.RequirePAR {
			snap.requirePAR = true
		}
		if !c.RequireSignedRequestObject {
			allRequireSignedRequestObject = false
		}
		if c.FrontchannelLogoutURI != "" {
			snap.frontchannelLogout = true
		}
		for _, sc := range c.AllowedScopes {
			if sc != "" {
				scopesSeen[sc] = struct{}{}
			}
		}
		for _, t := range c.AllowedAuthorizationDetailsTypes {
			if t != "" {
				adTypesSeen[t] = struct{}{}
			}
		}
	}
	snap.requireSignedRequestObject = allRequireSignedRequestObject
	snap.scopes = sortedKeys(scopesSeen)
	if len(adTypesSeen) > 0 {
		snap.authorizationDetailTypes = sortedKeys(adTypesSeen)
	}
	return snap
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DefaultDiscoveryDocCacheTTL re-exports oidc.DefaultDocCacheTTL for
// backward compat. See oidc/discovery_doc_cache.go for the full
// semantics + the CDN-aware tuning notes.
const DefaultDiscoveryDocCacheTTL = oidc.DefaultDocCacheTTL

// discoveryDocEntry aliases oidc.DocEntry so the Server cache holds
// the canonical type without exporting it from this package.
type discoveryDocEntry = oidc.DocEntry

// buildDiscoveryDocEntry delegates to oidc.BuildDocEntry.
func buildDiscoveryDocEntry(body []byte, ttl time.Duration) *discoveryDocEntry {
	return oidc.BuildDocEntry(body, ttl)
}

// lookupDiscoveryDocCache returns a fresh cached entry for base, or
// nil to signal "render fresh". The sync.Map keeps reads lock-free
// in the hot path.
func (s *Server) lookupDiscoveryDocCache(base string) *discoveryDocEntry {
	v, ok := s.discoveryDocCache.Load(base)
	if !ok {
		return nil
	}
	entry, _ := v.(*discoveryDocEntry)
	if entry.Fresh() {
		return entry
	}
	// Stale — drop so the next caller re-renders.
	s.discoveryDocCache.Delete(base)
	return nil
}

func (s *Server) storeDiscoveryDocCache(base string, entry *discoveryDocEntry) {
	s.discoveryDocCache.Store(base, entry)
}

// invalidateDiscoveryCaches drops both the derived discovery snapshot
// and every cached rendered document, so the next request recomputes
// from current client state. Local-only; never publishes (the bus
// subscriber calls this directly, and InvalidateDiscoveryCache is the
// publishing entry point).
func (s *Server) invalidateDiscoveryCaches() {
	s.discoveryCache.Store(nil)
	s.discoveryDocCache.Range(func(k, _ any) bool {
		s.discoveryDocCache.Delete(k)
		return true
	})
}

// InvalidateDiscoveryCache clears this replica's discovery snapshot +
// rendered-document caches and, when an invalidation bus is wired,
// publishes a reload so every other replica does the same. Wire this
// into admin handlers that mutate discovery-affecting client state
// (scopes, registration) so a config change converges across the
// cluster immediately rather than after each node's discovery cache
// TTL. Safe to call unconditionally; publish failures are logged, not
// propagated (peers fall back to their TTL).
func (s *Server) InvalidateDiscoveryCache() {
	s.invalidateDiscoveryCaches()
	s.InvalidateJWKSBodyCache()
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindDiscoveryReload}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "error", err)
		}
	}
}

// writeDiscoveryDoc delegates to oidc.WriteDoc with the server's
// configured cache TTL.
