package oauth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// CachedResult holds a cached introspection response body. The Body is a
// map[string]any so it round-trips through JSON identically to the original
// introspection response — every field (active, sub, iss, client_id, exp, iat,
// scope, etc.) is preserved as-is. LifecycleSubjects is internal enforcement
// metadata (sub followed by the RFC 8693 act chain), never emitted in the wire
// body. An inactive result contains only {"active": false}.
type CachedResult struct {
	Body              map[string]any
	LifecycleSubjects []string
}

// IntrospectionCache is the optional best-effort cache for token introspection
// results. Implementations must be safe for concurrent access.
//
// Security contract:
//   - The cache is BEST-EFFORT: a Set error (including a full cache) must
//     never block the request — verification proceeds normally (fail-open).
//   - The cache key MUST be a cryptographic hash of the token (not the raw
//     token), per the STORED-key-in-plaintext-is-a-leak principle.
//   - The cache TTL MUST be shorter than the token's remaining lifetime.
//   - A revoked token might be served from cache for up to TTL seconds.
//     This is INTENTIONAL eventual-consistency: without the cache, every
//     introspection on a high-traffic mesh pays full JWT signature
//     verification cost. Revocation call sites SHOULD narrow this window via
//     the OPTIONAL IntrospectionCacheInvalidator extension below (best-effort
//     — the TTL bound above still holds when a wired cache doesn't implement
//     it, or a caller doesn't invoke it).
type IntrospectionCache interface {
	// Get returns a cached introspection result. The bool is false on
	// a miss or an expired entry.
	Get(key string) (*CachedResult, bool)

	// Set stores an introspection result under key with the given TTL.
	// Implementations MUST handle ttl <= 0 by not storing (no-op) or by
	// using a configured default — callers pass the operator-configured
	// value directly.
	Set(key string, result *CachedResult, ttl time.Duration)
}

// IntrospectionCacheInvalidator is an OPTIONAL extension to IntrospectionCache
// — mirroring the oauthspi.RefreshTokenInspector / RefreshTokenFamilyTracker
// pattern of a separate, type-asserted capability interface — that lets a
// revocation path evict ONE cached result immediately, instead of waiting out
// the TTL. Implement it on the concrete cache type when the backend supports
// point deletes (MemoryIntrospectionCache does); a cache that can't (e.g. a
// write-through-only remote cache with no delete primitive) simply doesn't
// implement it, and every revocation path degrades to today's TTL-bounded
// eventual consistency — the SAME best-effort contract IntrospectionCache
// itself already carries, so this is purely additive and never a breaking
// change to the base SPI.
//
// Key MUST be the SAME derivation Get/Set use — SHA-256(token) hex, per
// tokenHash — never the raw token, preserving IntrospectionCache's
// never-store-plaintext contract. Callers should go through
// InvalidateIntrospectionCache below rather than computing the hash
// themselves, so every revocation call site agrees on the key derivation.
//
// FAIL-SAFE: Invalidate is a pure best-effort optimization, never a
// correctness gate for the revocation itself. A missed invalidation only
// widens the existing TTL window — it can never re-activate a token that was
// actually revoked at the source of truth (the issuer deny-set / refresh
// store delete), so implementations and callers MUST NOT let this block,
// retry, or fail the calling revocation path.
type IntrospectionCacheInvalidator interface {
	// Invalidate evicts the cached result for key (SHA-256(token) hex), if
	// present. A miss is a silent no-op — callers never know or care whether
	// anything was cached under key.
	Invalidate(key string)
}

// InvalidateIntrospectionCache evicts token's cached introspection result (if
// any) from cache, so a just-revoked token stops reporting a stale
// active:true immediately instead of waiting out the configured TTL
// (DefaultIntrospectionCacheTTL and friends). Every revocation call site
// (token/revoke, logout, revoke-all, admin revoke, cross-replica adopted
// revocation, refresh-family-reuse/velocity kill) SHOULD call this right
// after the actual revocation succeeds, passing the SAME raw token string
// that was revoked/consumed — this derives the identical SHA-256 key
// introspectOne used to populate the cache, so the RIGHT entry is evicted.
//
// No-op, byte-identical to calling nothing, when: cache is nil (caching
// disabled), token is empty, or the wired cache does not implement
// IntrospectionCacheInvalidator. Never returns an error and never blocks —
// see IntrospectionCacheInvalidator's FAIL-SAFE contract.
func InvalidateIntrospectionCache(cache IntrospectionCache, token string) {
	if cache == nil || token == "" {
		return
	}
	inv, ok := cache.(IntrospectionCacheInvalidator)
	if !ok {
		return
	}
	inv.Invalidate(tokenHash(token))
}

// introspectOne resolves ONE token's introspection body, consulting +
// populating the optional cache exactly as /token/introspect always has.
// Shared by the single-token path (serveIntrospectWithCache) and the batch
// path (serveIntrospectBatch) so caching behaves identically either way.
func introspectOne(d IntrospectDeps, ctx core.HandlerContext, token, hint string) map[string]any {
	// OPTIONAL cache check: keyed by SHA-256(token) so the raw token is
	// never stored in plaintext. When the cache is unwired, d.IntrospectionCache()
	// is nil and every call pays full verification, unchanged from before
	// this function was extracted.
	cache := d.IntrospectionCache()
	var cacheKey string
	if cache != nil {
		cacheKey = tokenHash(token)
		if cached, ok := cache.Get(cacheKey); ok {
			return lifecycleCheckedCachedResult(d, ctx, cache, cacheKey, token, cached)
		}
	}
	if body, subjects, ok := resolveIntrospection(d, ctx, token, hint); ok {
		if cache != nil {
			cache.Set(cacheKey, &CachedResult{Body: body, LifecycleSubjects: subjects}, d.IntrospectionCacheTTL())
		}
		return body
	}
	// Unknown / expired / revoked → §2.2 mandates {active: false} only.
	inactive := map[string]any{core.KeyActive: false}
	if cache != nil {
		cache.Set(cacheKey, &CachedResult{Body: inactive}, d.IntrospectionCacheTTL())
	}
	return inactive
}

func lifecycleCheckedCachedResult(d IntrospectDeps, ctx core.HandlerContext, cache IntrospectionCache, key, token string, cached *CachedResult) map[string]any {
	if cached == nil {
		return cacheInactiveIntrospection(cache, key, d.IntrospectionCacheTTL())
	}
	if cached.Body == nil {
		return cacheInactiveIntrospection(cache, key, d.IntrospectionCacheTTL())
	}
	if cached.Body[core.KeyActive] != true {
		return cached.Body
	}
	subjects := cached.LifecycleSubjects
	if len(subjects) == 0 {
		var active bool
		subjects, active = introspectionCacheSubjects(d, ctx, token, cached.Body)
		if !active {
			return cacheInactiveIntrospection(cache, key, d.IntrospectionCacheTTL())
		}
	}
	for _, subject := range subjects {
		if !introspectionLifecycleActive(d, ctx.Request().Context(), subject) {
			return cacheInactiveIntrospection(cache, key, d.IntrospectionCacheTTL())
		}
	}
	return cached.Body
}

func introspectionCacheSubjects(d IntrospectDeps, ctx core.HandlerContext, token string, body map[string]any) ([]string, bool) {
	subject, _ := body[core.KeySub].(string)
	if body[core.KeyTokenHint] != "access_token" {
		return []string{subject}, subject != "" && introspectionLifecycleActive(d, ctx.Request().Context(), subject)
	}
	claims, _, err := d.ValidateAnyToken(ctx.Request().Context(), token)
	if err != nil || claims == nil {
		return nil, false
	}
	return lifecycleSubjectsFromClaims(claims), true
}

func lifecycleSubjectsFromClaims(claims *core.TokenClaims) []string {
	if claims == nil {
		return nil
	}
	subjects := []string{claims.Subject}
	for actor := claims.Actor; actor != nil; actor = actor.Actor {
		subjects = append(subjects, actor.Subject)
	}
	return subjects
}

func cacheInactiveIntrospection(cache IntrospectionCache, key string, ttl time.Duration) map[string]any {
	inactive := map[string]any{core.KeyActive: false}
	cache.Set(key, &CachedResult{Body: inactive}, ttl)
	return inactive
}

// DefaultMaxIntrospectBatchSize is the fallback cap on how many tokens one
// batch /token/introspect request may include when the operator enabled
// batching (WithIntrospectionBatch) without an explicit size.
const DefaultMaxIntrospectBatchSize = 50

// introspectKeyResults is the wire key a batch response's array is nested
// under: {"results": [ <RFC 7662 body>, ... ]}, one entry per requested
// token in the SAME order as the request's `tokens` array.
const introspectKeyResults = "results"

// serveIntrospectBatch resolves every token in tokens (each exactly as a
// single /token/introspect call would, including the optional cache) and
// returns them as one JSON array under introspectKeyResults. A request over
// maxBatch is REJECTED with invalid_request rather than silently truncated —
// a caller must never mistake a partial batch for a complete one.
func serveIntrospectBatch(d IntrospectDeps, ctx core.HandlerContext, tokens []string, hint string, maxBatch int) {
	if len(tokens) > maxBatch {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	results := make([]map[string]any, 0, len(tokens))
	for _, t := range tokens {
		results = append(results, introspectOne(d, ctx, t, hint))
	}
	ctx.JSON(http.StatusOK, map[string]any{introspectKeyResults: results})
}

// --- RFC 9701 (JWT Response for OAuth Token Introspection) -----------------
//
// Relocated from handle_introspect.go (which was at the line budget).

// IntrospectionSigner is the seam RFC 9701 (JWT Response for OAuth Token
// Introspection) uses to sign the /token/introspect response. Structurally
// close to oidc.MetadataSigner/oidc.JARMSigner (SignMetadata), but kept as
// its OWN interface (own method name) so a general-purpose issuer type
// (Ed25519/ECDSA/RSA*JWTIssuer) can implement both roles as two distinct
// methods — the introspection method stamps the RFC 9701 §5.1 `typ`
// ("token-introspection+jwt") instead of the generic "JWT" typ JARM/
// metadata use, which is the RFC's defense against a resource server
// mistaking this response for a bearer access token.
//
// AGENTS.md requires this to be a DEDICATED key, never the issuer that
// mints access/ID tokens — wire a SEPARATE issuer instance via
// sso.WithIntrospectionSigning, mirroring the per-tenant-issuer pattern
// (WithTenantTokenIssuer) of an independently keyed + independently
// rotated named signer role rather than overloading the primary one.
type IntrospectionSigner interface {
	SignIntrospectionJWT(ctx context.Context, claims map[string]any) (string, error)
}

// JWKUseIntrospection is the "use" value stamped on the dedicated
// introspection signer's published JWK(s), distinguishing them in the
// aggregated /.well-known/jwks.json from the "sig" (access/ID token) and
// "enc" (JAR/response JWE) entries so a resource server can locate the
// right verification key without an out-of-band channel.
const JWKUseIntrospection = "introspection"

// IntrospectionKeySet decorates a core.JWKSProvider — typically the SAME
// dedicated issuer instance passed to sso.WithIntrospectionSigning — so
// its published JWKS entries carry "use": JWKUseIntrospection instead of
// the generic "sig" the general-purpose issuer types normally stamp. This
// keeps Ed25519/ECDSA/RSA*JWTIssuer free of a narrow, single-feature "use"
// value while still publishing the dedicated key through the existing
// JWKS aggregation path (see oidc.JWKSDeps.IntrospectionSigningKeys).
type IntrospectionKeySet struct {
	core.JWKSProvider
}

// NewIntrospectionKeySet wraps p. Returns nil when p is nil so callers can
// chain a possibly-absent signer's type assertion straight through without
// a separate nil check (a nil *IntrospectionKeySet stored in a non-nil
// interface would otherwise be a classic Go footgun).
func NewIntrospectionKeySet(p core.JWKSProvider) *IntrospectionKeySet {
	if p == nil {
		return nil
	}
	return &IntrospectionKeySet{JWKSProvider: p}
}

// JWKS re-publishes the wrapped provider's keys with Use overridden to
// JWKUseIntrospection. Every other field (kty/kid/alg/x/y/n/e) is passed
// through unchanged — only the usage tag differs.
func (k *IntrospectionKeySet) JWKS(ctx context.Context) ([]core.JWK, error) {
	keys, err := k.JWKSProvider.JWKS(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.JWK, len(keys))
	for i, jwk := range keys {
		jwk.Use = JWKUseIntrospection
		out[i] = jwk
	}
	return out, nil
}

// WantsIntrospectionJWT reports whether the request's Accept header asks
// for the RFC 9701 §5 JWT-formatted introspection response
// (core.ContentTypeTokenIntrospectionJWT). Matches like the existing
// acceptsHTML/acceptsJSON content-negotiation helpers elsewhere in this
// codebase — a raw substring check rather than full RFC 9110 media-range
// parsing (q-values, wildcards), which is more precision than a single
// exact media type warrants.
func WantsIntrospectionJWT(accept string) bool {
	return strings.Contains(accept, core.ContentTypeTokenIntrospectionJWT)
}

// SignIntrospectionResponse signs body (the already-computed RFC 7662
// introspection map — active:false or the populated active:true shape)
// into the RFC 9701 JWT wrapper. Per §5.1: iss identifies this AS, aud
// identifies the introspecting client (the resource server that will
// consume the response), iat is the signing moment. sub/exp are
// deliberately NEVER set at the top level (§8 substitution-attack
// defense) — the entire introspection payload, including any exp/sub it
// carries, lives ONLY inside the nested core.KeyTokenIntrospection claim.
func SignIntrospectionResponse(ctx context.Context, signer IntrospectionSigner, issuer, clientID string, body map[string]any) (string, error) {
	claims := map[string]any{
		core.KeyIss:                issuer,
		core.KeyAud:                clientID,
		core.KeyIat:                time.Now().Unix(),
		core.KeyTokenIntrospection: body,
	}
	return signer.SignIntrospectionJWT(ctx, claims)
}
