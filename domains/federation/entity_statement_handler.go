package federation

import (
	"sync"
	"time"
)

// EntityHandler holds the immutable federation-entity wiring: the operator
// config, the signer (the OP's signing issuer reused via its SignJWT seam),
// the response cache, and the trust-chain resolver (slice 2). Constructed once
// at server build time and shared across requests (both the cache and the
// resolver are concurrency-safe). A nil *EntityHandler on the Server means the
// federation route is not mounted.
type EntityHandler struct {
	cfg        *Config
	signer     JWTSigner
	cache      *EntityConfigCache
	fetchCache *SubordinateStatementCache
	resolver   *TrustChainResolver
}

// NewEntityHandler builds an EntityHandler. Both cfg and signer MUST be
// non-nil for the handler to be usable; the SDK option guards that and
// leaves the Server's field nil (route unmounted) otherwise. The trust-chain
// resolver is built from the SAME config; it is inert (Resolver().Enabled() ==
// false) until the operator configures trust anchors, so a config with no
// anchors keeps slice-1 behavior (the resolver is never invoked) byte-
// identical.
func NewEntityHandler(cfg *Config, signer JWTSigner, resolverOpts ...TrustChainResolverOption) *EntityHandler {
	return &EntityHandler{
		cfg:        cfg,
		signer:     signer,
		cache:      NewEntityConfigCache(),
		fetchCache: NewSubordinateStatementCache(),
		resolver:   NewTrustChainResolver(cfg, resolverOpts...),
	}
}

// Config returns the wired federation config (used by the Deps accessor so
// the handler reads TTLs + authority_hints + federation_entity fields).
func (h *EntityHandler) Config() *Config { return h.cfg }

// Signer returns the wired federation JWT signer.
func (h *EntityHandler) Signer() JWTSigner { return h.signer }

// Cache returns the per-issuer Entity Configuration cache.
func (h *EntityHandler) Cache() *EntityConfigCache { return h.cache }

// FetchCache returns the per-(issuer, subordinate) Subordinate Statement cache
// the §8 Federation Fetch endpoint (fetch.go) uses. Never nil for a
// constructed handler.
func (h *EntityHandler) FetchCache() *SubordinateStatementCache { return h.fetchCache }

// HasSubordinates reports whether this server is configured as a federation
// SUPERIOR (≥1 subordinate). Gates the §8 route mount + the
// federation_fetch_endpoint advertisement (slice-1 byte-identical when false).
func (h *EntityHandler) HasSubordinates() bool { return h.cfg.hasSubordinates() }

// Resolver returns the trust-chain resolver (slice 2). Slice 3 (federation
// client registration) calls Resolver().ResolveTrustChain to validate a remote
// RP's chain up to a configured trust anchor before standing in for out-of-
// band registration. The resolver is inert (returns ErrFederationResolver
// Disabled) until trust anchors are configured. Never nil for a constructed
// handler.
func (h *EntityHandler) Resolver() *TrustChainResolver { return h.resolver }

// entityConfigEntry is one cached, signed Entity Configuration for a given
// issuer URL. compact is the full signed JWS; etag/expiresAt drive the
// HTTP-layer ETag + freshness, mirroring the discovery doc entry. Treated
// as immutable after publication.
type entityConfigEntry struct {
	compact   []byte
	etag      string
	expiresAt time.Time
}

// fresh reports whether the cached entry is still within its TTL. nil-safe.
func (e *entityConfigEntry) fresh(now time.Time) bool {
	return e != nil && now.Before(e.expiresAt)
}

// EntityConfigCache caches the signed Entity Configuration per issuer URL.
// Keyed by issuer (not request base URL) because the statement's iss/sub —
// and therefore the signed bytes — are determined by the resolved issuer;
// the same multi-host server can resolve different issuers, and each gets
// its own cached signature. Reads are sync.Map-served lock-free.
type EntityConfigCache struct {
	m sync.Map // issuer(string) -> *entityConfigEntry
}

// NewEntityConfigCache returns an empty cache.
func NewEntityConfigCache() *EntityConfigCache { return &EntityConfigCache{} }

// lookup returns a fresh cached entry for issuer, or nil on miss/stale.
func (c *EntityConfigCache) lookup(issuer string, now time.Time) *entityConfigEntry {
	v, ok := c.m.Load(issuer)
	if !ok {
		return nil
	}
	e, _ := v.(*entityConfigEntry)
	if !e.fresh(now) {
		return nil
	}
	return e
}

// store publishes an entry for issuer.
func (c *EntityConfigCache) store(issuer string, e *entityConfigEntry) {
	c.m.Store(issuer, e)
}
