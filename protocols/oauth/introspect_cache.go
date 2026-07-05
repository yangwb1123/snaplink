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

// introspectionJWTMediaType is the RFC 9701 §5 media type a client sets on
// its Accept header to opt into a JWT-signed introspection response instead
// of plain RFC 7662 JSON.
const introspectionJWTMediaType = "application/token-introspection+jwt"

// introspectKeyTokenIntrospection nests the RFC 7662 result under a claim
// name distinct from top-level sub/exp/etc (RFC 9701 §8 substitution-attack
// defense): a validator that doesn't specifically check for this claim (or
// the typ header) can't mistake the signed introspection response for a
// bearer access token about the introspecting client itself.
const introspectKeyTokenIntrospection = "token_introspection"

// IntrospectionSigner is the seam HandleIntrospect uses to produce a signed
// JWT introspection response — this server's introspection-side analogue of
// JARM (oidc.JARMSigner) and signed discovery metadata (oidc.MetadataSigner).
// Structurally identical to both (the same SignMetadata method) so the SAME
// already-wired signing key can satisfy all three without protocols/oauth
// importing protocols/oidc (prohibited, AGENTS.md §0.2) or a new key ever
// being minted. Pragmatic subset of RFC 9701: it reuses the existing
// signer's fixed `typ` header (rather than adding a dedicated
// `token-introspection+jwt` typ, which would need a new method on every
// defaultimpl issuer) and relies on the nested introspectKeyTokenIntrospection
// claim for the substitution defense instead.
type IntrospectionSigner interface {
	SignMetadata(ctx context.Context, claims map[string]any) (string, error)
}

// writeSignedIntrospection signs body into a JWT and writes it when the
// client opted in (Accept: application/token-introspection+jwt) AND a
// signer is wired via WithIntrospectionSigner. Returns true when it has
// written the response: either a signed success, or — FAIL-CLOSED — a
// signing failure, since silently downgrading to plaintext JSON after the
// client explicitly asked for an authenticated response would defeat the
// point. False means the caller must fall through to plain JSON: the client
// didn't ask, or (the default) no signer is wired — byte-identical either
// way to a build without this feature.
func writeSignedIntrospection(d IntrospectDeps, ctx core.HandlerContext, aud string, body map[string]any) bool {
	signer := d.IntrospectionSigner()
	if signer == nil || !wantsSignedIntrospection(ctx) {
		return false
	}
	claims := map[string]any{
		core.KeyIss:                     d.ResolveIssuer(ctx),
		core.KeyIat:                     time.Now().Unix(),
		introspectKeyTokenIntrospection: body,
	}
	if aud != "" {
		claims[core.KeyAud] = aud
	}
	jwt, err := signer.SignMetadata(ctx.Request().Context(), claims)
	if err != nil || jwt == "" {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return true
	}
	w := ctx.ResponseWriter()
	w.Header().Set(core.HeaderContentType, introspectionJWTMediaType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jwt))
	return true
}

// wantsSignedIntrospection reports whether the request's Accept header
// includes the RFC 9701 §5 signed-introspection media type. A plain
// substring check (not full RFC 7231 Accept parsing with q-values/wildcards)
// — adequate for a client that deliberately opts in.
func wantsSignedIntrospection(ctx core.HandlerContext) bool {
	return strings.Contains(ctx.Request().Header.Get(core.HeaderAccept), introspectionJWTMediaType)
}
