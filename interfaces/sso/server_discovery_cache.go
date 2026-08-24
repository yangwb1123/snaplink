package sso

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/protocols/oauth/scoperegistry"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

func WithDiscoveryCacheTTL(d time.Duration) Option {
	return func(s *Server) { s.discoveryCacheTTL = d }
}

// WithServingRegionAdvertisement pins this deployment's serving region for
// DISCOVERY advertisement. The value MUST be deployment-static: the
// discovery document is cached per base URL, and every minted token in this
// process must carry the same serving_region. Wire it together with
// WithRegionMiddleware so advertised == minted. A header-resolver-only
// deployment (region varies per request) MUST NOT wire this. Empty (the
// default) omits the field and the claims_supported entry — byte-identical.
func WithServingRegionAdvertisement(id region.ID) Option {
	return func(s *Server) { s.servingRegionAdvertisement = id }
}

// applyServingRegionMetadata advertises the pinned serving region. Runs
// AFTER applyStaticClaimsAndSecurity because that helper ASSIGNS a fresh
// ClaimsSupported literal; appending here avoids the overwrite.
func (s *Server) applyServingRegionMetadata(cfg *oidc.ProviderMetadata) {
	if s.servingRegionAdvertisement == "" {
		return
	}
	cfg.ServingRegion = string(s.servingRegionAdvertisement)
	cfg.ClaimsSupported = append(cfg.ClaimsSupported, core.KeyServingRegion)
}

// baseAdvertisedGrants is the set of grant types ALWAYS advertised in
// discovery, independent of optional store wiring. device_code and CIBA are
// conditionally appended in applyGrantEndpoints only when their store is wired
// (RFC 8414 §2: advertise only what is actually supported — /device/* and the
// device token grant return 501 when WithDeviceCodeStore is omitted). This is
// deliberately NARROWER than core.SupportedGrants, which stays the full
// recognized set for unsupported_grant_type errors.
func baseAdvertisedGrants() []string {
	return []string{
		GrantAuthorizationCode,
		GrantRefreshToken,
		GrantClientCredentials,
		GrantTokenExchange,
	}
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
	proj := projectClientFields(clients, s.idTokenIssuer != nil)
	snap.requirePAR = proj.requirePAR
	snap.frontchannelLogout = proj.frontchannelLogout
	snap.requireSignedRequestObject = proj.requireSignedRequestObject
	// Under an enabled scope registry, scopes_supported MUST NOT advertise a
	// scope /token would reject: filter the client-set union through the
	// registry (a client with AllowedScopes=["anything"] is advertised
	// "anything" today and 400s every /token request naming it once the
	// registry is on). Registry-off (nil) is byte-identical — the full
	// union. OIDC standard scopes survive because the registry pre-registers
	// them; the filter covers OIDC discovery, RFC 8414 resource metadata,
	// federation, and signed metadata (all derive from this snapshot).
	snap.scopes = scoperegistry.FilterRegistered(s.scopeRegistry, proj.scopes)
	snap.authorizationDetailTypes = proj.authorizationDetailTypes
	return snap
}

// discoveryClientProjection holds the discovery-relevant aggregate fields
// derived from the client set by projectClientFields.
type discoveryClientProjection struct {
	scopes                     []string
	authorizationDetailTypes   []string
	requirePAR                 bool
	requireSignedRequestObject bool
	frontchannelLogout         bool
}

// projectClientFields derives the aggregate discovery fields from the client
// set. hasIDTokenIssuer seeds the openid scope (mirrors the snapshot's
// idTokenIssuer-gated default). requireSignedRequestObject starts true only
// when the set is non-empty and a nil client forces it false (an unreadable
// client can't be proven to require signed requests) and is otherwise skipped
// — identical to the original inline loop.
func projectClientFields(clients []*core.Client, hasIDTokenIssuer bool) discoveryClientProjection {
	scopesSeen := map[string]struct{}{}
	if hasIDTokenIssuer {
		scopesSeen[ScopeOpenID] = struct{}{}
	}
	adTypesSeen := map[string]struct{}{}
	proj := discoveryClientProjection{requireSignedRequestObject: len(clients) > 0}
	for _, c := range clients {
		projectClient(&proj, scopesSeen, adTypesSeen, c)
	}
	proj.scopes = sortedKeys(scopesSeen)
	if len(adTypesSeen) > 0 {
		proj.authorizationDetailTypes = sortedKeys(adTypesSeen)
	}
	return proj
}

func projectClient(
	proj *discoveryClientProjection,
	scopesSeen, adTypesSeen map[string]struct{},
	client *core.Client,
) {
	if client == nil {
		proj.requireSignedRequestObject = false
		return
	}
	proj.requirePAR = proj.requirePAR || client.RequirePAR
	proj.requireSignedRequestObject = proj.requireSignedRequestObject && client.RequireSignedRequestObject
	proj.frontchannelLogout = proj.frontchannelLogout || client.FrontchannelLogoutURI != ""
	addNonEmptyStrings(scopesSeen, client.AllowedScopes)
	addNonEmptyStrings(adTypesSeen, client.AllowedAuthorizationDetailsTypes)
}

func addNonEmptyStrings(seen map[string]struct{}, values []string) {
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
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

// flushInvalidationCaches drops every local TTL cache a lost invalidation
// Event could have targeted, so the next read of each re-fetches from its
// authoritative store. Called on invalidation-bus recovery
// (resubscribeAndReseed): the lost events' keys are unknowable, so the only
// safe convergence is a full flush of every kind applyInvalidation serves —
// tenant suspension, tenant residency, client metadata, discovery snapshot +
// rendered docs + JWKS body, and authz-policy bundles. Local-only; never
// publishes. All flushes are infallible; the fallible half of recovery
// re-seeding (revocation deny-sets) is separate so its error can keep the
// replica degraded.
func (s *Server) flushInvalidationCaches() {
	if s.tenantSuspensionCache != nil {
		s.tenantSuspensionCache.flush()
	}
	if s.tenantResidencyCache != nil {
		s.tenantResidencyCache.flush()
	}
	if s.clientStoreCacheRef != nil {
		s.clientStoreCacheRef.EvictAll()
	}
	s.invalidateDiscoveryCaches()
	s.InvalidateJWKSBodyCache()
	// Whole-cache sweep (vs. the per-client prefix sweep of
	// invalidateAuthzPolicyBundleCacheLocal) — the lost event's clientID is
	// unknown.
	s.authzPolicyBundleCache.Range(func(k, _ any) bool {
		s.authzPolicyBundleCache.Delete(k)
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

// WithIDTokenIssuerAlg wires a DEDICATED id_token issuer for clients that
// declare `id_token_signed_response_alg: <alg>` (OIDC Core §3.1.3.1 / RFC
// 7591 §2 client metadata) — the product-level FAPI unblock: an RS256 login
// client can coexist with ES256/PS256 FAPI clients on one issuer because each
// RP's ID tokens are signed with the algorithm IT declared. The issuer MUST
// also be registered via WithTokenIssuer so its public key lands in the
// aggregated /.well-known/jwks.json and id_token_hint validation (silent
// renewal / end_session) can verify tokens it signs. The default issuer
// (WithIDTokenIssuer) stays untouched — clients without the field keep the
// legacy resolution, byte-identical.
//
// alg is validated against the server's accepted JWS algorithm set
// (security.AsymmetricJWSAlgs: EdDSA, ES256/384/512, RS256, PS256 — AGENTS.md
// §3); anything else — including "none" — panics at construction, mirroring
// WithRSAAlg's unsupported-alg panic.
func WithIDTokenIssuerAlg(alg string, issuer oidc.IDTokenIssuer) Option {
	return func(s *Server) {
		if _, ok := security.AsymmetricJWSAlgs()[alg]; !ok {
			panic(fmt.Sprintf("sso: unsupported id_token_signed_response_alg %q (want EdDSA, ES256/384/512, RS256, or PS256)", alg))
		}
		if s.idTokenIssuerAlgs == nil {
			s.idTokenIssuerAlgs = make(map[string]oidc.IDTokenIssuer)
		}
		s.idTokenIssuerAlgs[alg] = issuer
	}
}

// IDTokenSigningAlgValues returns the JWS algs this server can sign ID
// Tokens with: the default issuer's live signing set (SigningAlgValues)
// unioned with every alg wired via WithIDTokenIssuerAlg, deduped and sorted.
// It is the SAME set discovery advertises as
// id_token_signing_alg_values_supported AND the set DCR validation accepts
// for id_token_signed_response_alg, so registration and advertisement can
// never disagree. Byte-identical to SigningAlgValues when no per-alg issuers
// are wired.
func (s *Server) IDTokenSigningAlgValues(ctx context.Context) []string {
	base := s.SigningAlgValues(ctx)
	if len(s.idTokenIssuerAlgs) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base)+len(s.idTokenIssuerAlgs))
	for _, a := range base {
		seen[a] = struct{}{}
	}
	for a := range s.idTokenIssuerAlgs {
		seen[a] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// writeDiscoveryDoc delegates to oidc.WriteDoc with the server's
// configured cache TTL.
