package federation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// Deps is what HandleEntityConfiguration needs from the host server.
// *sso.Server satisfies it via accessor methods (accessors.go). Defined as
// an interface (the hexagonal seam) so the handler body lives in this
// package — which never imports root sso — while the root delegates a
// one-liner to it.
type Deps interface {
	// ResolveIssuer returns the issuer URL for this request (honoring the
	// configured issuer override + the X-Forwarded edge-trust contract).
	// For a self-signed Entity Configuration this is BOTH iss and sub.
	ResolveIssuer(ctx core.HandlerContext) string
	// TokenIssuers returns the registered strategy -> TokenIssuer map. The
	// handler walks it for every issuer satisfying core.JWKSProvider to
	// assemble the inline jwks (the SAME aggregation the /jwks.json handler
	// performs) — so the Entity Statement's keys are exactly the OP's
	// published signing keys.
	TokenIssuers() map[string]core.TokenIssuer
	// BuildOPMetadata projects the openid_provider metadata for base URL,
	// DERIVED from the discovery document so the federation view cannot
	// drift from the discovery view.
	BuildOPMetadata(ctx core.HandlerContext, base string) OPFederationMetadata
	// FederationSigner is the OP signing issuer reused via its SignJWT seam
	// (typ entity-statement+jwt). The statement's kid is one of the keys in
	// its own jwks, so a verifier validates it against a trusted key.
	FederationSigner() JWTSigner
	// FederationConfig carries authority_hints, federation_entity fields,
	// and the TTLs.
	FederationConfig() *Config
	// RequestBaseURL derives the absolute scheme://host base for this
	// request (the SAME derivation the discovery doc uses). Exposed via Deps
	// — rather than computed here — so this package depends only on core +
	// security and never reaches into the middleware base-URL extractor.
	RequestBaseURL(ctx core.HandlerContext) string
	// FederationCache is the per-issuer signed-statement cache.
	FederationCache() *EntityConfigCache
	// FederationNow is the clock the handler stamps iat/exp from. Injected
	// (not a direct time.Now call) so a test can drive a fixed time through
	// BOTH the handler and its assertions, keeping exp deterministic — no
	// real-clock-vs-fixed-time date bomb.
	FederationNow() time.Time
	// LogError logs a non-fatal error (signing/marshal failure). Mirrors the
	// server logger used by the discovery signed_metadata path.
	LogError(msg string, args ...any)
}

// HandleEntityConfiguration serves GET /.well-known/openid-federation — the
// OP's self-signed Entity Configuration (OpenID Federation 1.0 §9). It:
//
//  1. resolves the issuer (iss == sub, the self-signed entity identifier);
//  2. assembles the inline jwks from every JWKSProvider TokenIssuer (the
//     OP's published signing keys, so the statement is verifiable against a
//     key a consumer already trusts);
//  3. derives openid_provider metadata from the discovery doc and adds the
//     federation_entity metadata from config;
//  4. builds the Entity Statement claims and signs them via the OP's
//     SignJWT seam with typ entity-statement+jwt;
//  5. ETag + Cache-Control caches + writes the signed JWS (public metadata,
//     so public max-age, NOT no-store).
//
// A signing/marshal failure logs + returns 500 (mirroring the discovery
// signed_metadata 500 path). NO new wire error code is introduced.
//
// This slice performs NO trust-chain resolution: authority_hints are
// emitted but never followed. Validating the chain up to a trust anchor is
// the trust boundary and a separate slice.
func HandleEntityConfiguration(deps Deps, ctx core.HandlerContext) {
	cfg := deps.FederationConfig()
	now := deps.FederationNow()
	base := deps.RequestBaseURL(ctx)
	iss := deps.ResolveIssuer(ctx)

	// Body cache keyed by issuer: skip the jwks walk + metadata build +
	// SIGN when a recent rendering is still fresh. Signing can be a KMS
	// round-trip (5-50ms), so caching matters under federation-resolver
	// polling. Honors If-None-Match → 304 via WriteEntityStatement.
	cache := deps.FederationCache()
	if cache != nil {
		if entry := cache.lookup(iss, now); entry != nil {
			WriteEntityStatement(ctx.ResponseWriter(), ctx.Request(), entry.compact, entry.etag, cfg.cacheTTL())
			return
		}
	}

	// Inline jwks: aggregate every JWKSProvider issuer's keys — the SAME
	// walk /jwks.json performs. These are the OP's published signing keys;
	// the Entity Statement is signed by one of them (kid match), so a
	// consumer validates it with no new trust setup (the key-reuse crux).
	keys := aggregateIssuerJWKS(deps, ctx)

	// openid_provider metadata is DERIVED from the discovery doc (via the
	// OP projection) so the two views never diverge. federation_entity is
	// the federation-level contact/org metadata from config.
	meta := buildEntityMetadata(deps, ctx, cfg, base)

	claims := entityConfigurationClaims(iss, keys, meta, cfg, now)

	compact, err := deps.FederationSigner().SignJWT(ctx.Request().Context(), EntityStatementTyp, claims)
	if err != nil {
		// Mirror the discovery signed_metadata failure: log + 500. The
		// signed Entity Configuration is the whole response (unlike
		// signed_metadata, which is one field of an otherwise-serveable
		// doc), so there is nothing to fall back to.
		deps.LogError("federation: entity configuration signing failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}

	body := []byte(compact)
	etag := buildETag(body)
	if cache != nil {
		cache.store(iss, &entityConfigEntry{compact: body, etag: etag, expiresAt: now.Add(cfg.cacheTTL())})
	}
	WriteEntityStatement(ctx.ResponseWriter(), ctx.Request(), body, etag, cfg.cacheTTL())
}

// aggregateIssuerJWKS aggregates the OP's published signing keys from every
// JWKSProvider TokenIssuer — the SAME walk /jwks.json performs. A provider that
// errors is logged + skipped (the Entity Statement still publishes the keys
// that did resolve; one broken issuer must not blank the whole jwks).
func aggregateIssuerJWKS(deps Deps, ctx core.HandlerContext) []core.JWK {
	keys := make([]core.JWK, 0)
	for _, ti := range deps.TokenIssuers() {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		ks, err := jp.JWKS(ctx.Request().Context())
		if err != nil {
			deps.LogError("federation: jwks provider failed", "error", err)
			continue
		}
		keys = append(keys, ks...)
	}
	return keys
}

// buildEntityMetadata assembles the Entity Configuration's metadata: the
// openid_provider projection (DERIVED from the discovery doc so the two views
// never diverge) plus, when present, the federation_entity entry (org/contacts
// + the §8 federation_fetch_endpoint when this server is a superior).
func buildEntityMetadata(deps Deps, ctx core.HandlerContext, cfg *Config, base string) *EntityMetadata {
	opMeta := deps.BuildOPMetadata(ctx, base)
	meta := &EntityMetadata{OP: &opMeta}
	if fe := federationEntityMeta(cfg, base); fe != nil {
		meta.FederationEntity = fe
	}
	return meta
}

// entityConfigurationClaims builds the self-signed Entity Configuration claims
// (iss == sub == entity identifier), stamping iat/exp from now + the configured
// TTL and carrying the aggregated jwks, metadata, and authority_hints.
func entityConfigurationClaims(iss string, keys []core.JWK, meta *EntityMetadata, cfg *Config, now time.Time) EntityStatementClaims {
	ttl := cfg.entityStatementTTL()
	return EntityStatementClaims{
		Iss:            iss,
		Sub:            iss,
		Iat:            now.Unix(),
		Exp:            now.Add(ttl).Unix(),
		JWKS:           EntityJWKS{Keys: keys},
		Metadata:       meta,
		AuthorityHints: authorityHints(cfg),
	}
}

// federationEntityMeta builds the federation_entity metadata entry from
// config, or nil when the operator configured neither org/contacts NOR any
// subordinate NOR any trust anchor (so the entry is omitted from the statement
// rather than emitted empty — keeping the slice-1 leaf-OP entity config
// byte-identical).
//
// When subordinates ARE configured this server is a federation SUPERIOR, so the
// entry additionally advertises the §8 federation_fetch_endpoint
// (base + PathFederationFetch) — that is the ONLY thing that makes a resolver
// climb THROUGH this server (superiorFetchEndpoint reads exactly this field).
// The endpoint must therefore be present whenever subordinates are, even if
// org/contacts are empty.
//
// When trust anchors ARE configured this server is a Trust Anchor, so the
// entry additionally advertises the §8.3 federation_resolve_endpoint
// (base + PathFederationResolve) so a resolver or relying party can use this
// server to resolve a trust chain.
func federationEntityMeta(cfg *Config, base string) *FederationEntityMeta {
	if cfg == nil {
		return nil
	}
	hasSubs := cfg.hasSubordinates()
	hasAnchors := len(cfg.TrustAnchors) > 0
	if cfg.OrganizationName == "" && len(cfg.Contacts) == 0 && !hasSubs && !hasAnchors {
		return nil
	}
	fe := &FederationEntityMeta{
		OrganizationName: cfg.OrganizationName,
		Contacts:         append([]string(nil), cfg.Contacts...),
	}
	if hasSubs {
		fe.FederationFetchEndpoint = base + core.PathFederationFetch
		fe.FederationListEndpoint = base + core.PathFederationList
	}
	if hasAnchors {
		fe.FederationResolveEndpoint = base + core.PathFederationResolve
	}
	// Trust Mark Status endpoint — advertised when the path is configured.
	fe.FederationTrustMarkStatusEndpoint = base + core.PathFederationTrustMarkStatus
	return fe
}

// authorityHints returns a defensive copy of the configured authority_hints
// (nil when none, so the claim is omitted).
func authorityHints(cfg *Config) []string {
	if cfg == nil || len(cfg.AuthorityHints) == 0 {
		return nil
	}
	return append([]string(nil), cfg.AuthorityHints...)
}


// HistoricalKey records one previously-used signing key.
type HistoricalKey struct {
	// KID is the key identifier that was used in the JWK.
	KID string `json:"kid"`

	// JWK is the JSON Web Key (public portion only).
	JWK map[string]any `json:"jwk"`

	// ActiveFrom is when this key was first published.
	ActiveFrom time.Time `json:"active_from"`

	// ActiveUntil is when this key was rotated out (zero = still potentially active).
	ActiveUntil time.Time `json:"active_until,omitempty"`

	// RetiredAt is when this key was formally retired.
	RetiredAt time.Time `json:"retired_at,omitempty"`
}

// HistoricalKeyStore persists retired signing keys.
type HistoricalKeyStore interface {
	// RecordKey persists a newly-retired key alongside its active window.
	RecordKey(ctx context.Context, key *HistoricalKey) error

	// HistoricalKeys returns all recorded historical keys ordered by
	// active_from descending (most recent first).
	HistoricalKeys(ctx context.Context) ([]*HistoricalKey, error)

	// HistoricalKeysByKID returns a specific historical key by its KID.
	HistoricalKeysByKID(ctx context.Context, kid string) (*HistoricalKey, error)
}

// ErrKeyNotFound is returned when a historical key is not found.
var ErrKeyNotFound = errors.New("federation: historical key not found")

// MemoryHistoricalKeyStore is an in-memory HistoricalKeyStore.
type MemoryHistoricalKeyStore struct {
	mu    sync.RWMutex
	keys  map[string]*HistoricalKey
	order []string // KID order by active_from desc
}

// NewMemoryHistoricalKeyStore returns an empty in-memory historical key store.
func NewMemoryHistoricalKeyStore() *MemoryHistoricalKeyStore {
	return &MemoryHistoricalKeyStore{
		keys: make(map[string]*HistoricalKey),
	}
}

func (s *MemoryHistoricalKeyStore) RecordKey(_ context.Context, key *HistoricalKey) error {
	if key.KID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		key.KID = "hk_" + hex.EncodeToString(b)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.KID] = key
	s.rebuildOrder()
	return nil
}

func (s *MemoryHistoricalKeyStore) HistoricalKeys(_ context.Context) ([]*HistoricalKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*HistoricalKey, 0, len(s.order))
	for _, kid := range s.order {
		if k, ok := s.keys[kid]; ok {
			out = append(out, k)
		}
	}
	return out, nil
}

func (s *MemoryHistoricalKeyStore) HistoricalKeysByKID(_ context.Context, kid string) (*HistoricalKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

func (s *MemoryHistoricalKeyStore) rebuildOrder() {
	s.order = make([]string, 0, len(s.keys))
	for kid := range s.keys {
		s.order = append(s.order, kid)
	}
	sort.Slice(s.order, func(i, j int) bool {
		return s.keys[s.order[i]].ActiveFrom.After(s.keys[s.order[j]].ActiveFrom)
	})
}

// compile-time interface checks.
var (
	_ HistoricalKeyStore = (*MemoryHistoricalKeyStore)(nil)
)
