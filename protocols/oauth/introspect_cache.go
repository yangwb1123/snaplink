package oauth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// CachedResult holds a cached introspection response body. The Body is a
// map[string]any so it round-trips through JSON identically to the original
// introspection response — every field (active, sub, iss, client_id, exp, iat,
// scope, etc.) is preserved as-is. An inactive result contains only
// {"active": false}.
type CachedResult struct {
	Body map[string]any
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
//     verification cost.
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
			return cached.Body
		}
	}
	if body, ok := resolveIntrospection(d, ctx, token, hint); ok {
		if cache != nil {
			cache.Set(cacheKey, &CachedResult{Body: body}, d.IntrospectionCacheTTL())
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
