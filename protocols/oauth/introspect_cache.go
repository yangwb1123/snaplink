package oauth

import "time"

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
