package handler

import (
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// memoryCacheEntry pairs a cached result with its freshness deadline.
type memoryCacheEntry struct {
	result    *oauth.CachedResult
	expiresAt time.Time
}

// MemoryIntrospectionCache is an in-process, concurrent-safe TTL cache for
// token introspection results. It uses sync.Map for lock-free reads and
// lazily evicts expired entries on read (no background sweeper needed for
// the expected low-cardinality, short-TTL workload).
//
// Expected usage: one instance per server process. Multi-replica deployments
// that want a shared cache must wire a different IntrospectionCache backend
// (e.g. Redis); this in-memory store gives each replica its own independent
// window — the eventual-consistency tradeoff is unchanged, just per-replica.
type MemoryIntrospectionCache struct {
	entries sync.Map
}

// NewMemoryIntrospectionCache creates an empty MemoryIntrospectionCache.
func NewMemoryIntrospectionCache() *MemoryIntrospectionCache {
	return &MemoryIntrospectionCache{}
}

// Get returns a cached result when a non-expired entry exists. Expired
// entries are lazily removed on read.
func (m *MemoryIntrospectionCache) Get(key string) (*oauth.CachedResult, bool) {
	v, ok := m.entries.Load(key)
	if !ok {
		return nil, false
	}
	entry := v.(memoryCacheEntry)
	if time.Since(entry.expiresAt) > 0 {
		m.entries.Delete(key)
		return nil, false
	}
	return entry.result, true
}

// Set stores a result with a TTL. A ttl <= 0 is treated as a no-op.
func (m *MemoryIntrospectionCache) Set(key string, result *oauth.CachedResult, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	m.entries.Store(key, memoryCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	})
}

// Invalidate evicts the cached entry for key immediately, if present — a
// miss is a no-op (sync.Map.Delete tolerates a missing key). Implements
// oauth.IntrospectionCacheInvalidator so a revocation path can close the
// TTL-bounded eventual-consistency window instead of waiting it out.
func (m *MemoryIntrospectionCache) Invalidate(key string) {
	m.entries.Delete(key)
}

// Compile-time guard: MemoryIntrospectionCache also satisfies the OPTIONAL
// invalidation extension, not just the base IntrospectionCache contract.
var _ oauth.IntrospectionCacheInvalidator = (*MemoryIntrospectionCache)(nil)

// timeNow is a package-level var for test injection. Deprecated: use
// time.Now() directly; monotonic comparison is now handled by time.Since
// in Get() which does not depend on this var.
var timeNow = time.Now

// NoopIntrospectionCache is a no-op implementation that never caches
// anything. It is the default when WithIntrospectionCache is not wired,
// making every cache check a no-op with zero overhead.
type NoopIntrospectionCache struct{}

// Get always returns (nil, false).
func (NoopIntrospectionCache) Get(_ string) (*oauth.CachedResult, bool) { return nil, false }

// Set is a no-op.
func (NoopIntrospectionCache) Set(_ string, _ *oauth.CachedResult, _ time.Duration) {}
