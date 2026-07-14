package handler

import (
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
)

// TestMemoryIntrospectionCache_Invalidate proves the OPTIONAL
// oauth.IntrospectionCacheInvalidator extension: a cached entry is gone
// immediately after Invalidate, rather than surviving until its TTL expires,
// and invalidating a key that was never cached (or already evicted) is a
// silent no-op — matching sync.Map.Delete's tolerance of a missing key.
func TestMemoryIntrospectionCache_Invalidate(t *testing.T) {
	t.Parallel()

	t.Run("evicts a live entry immediately", func(t *testing.T) {
		c := NewMemoryIntrospectionCache()
		c.Set("key-1", &oauth.CachedResult{Body: map[string]any{"active": true}}, time.Minute)
		if _, ok := c.Get("key-1"); !ok {
			t.Fatal("precondition: entry must be cached before invalidating it")
		}
		c.Invalidate("key-1")
		if _, ok := c.Get("key-1"); ok {
			t.Fatal("entry survived Invalidate — TTL-bounded staleness was not closed")
		}
	})

	t.Run("invalidating an unknown key is a no-op", func(t *testing.T) {
		c := NewMemoryIntrospectionCache()
		c.Invalidate("never-cached") // must not panic or error
		if _, ok := c.Get("never-cached"); ok {
			t.Fatal("Get on a never-cached key must still miss")
		}
	})

	t.Run("invalidating twice is idempotent", func(t *testing.T) {
		c := NewMemoryIntrospectionCache()
		c.Set("key-2", &oauth.CachedResult{Body: map[string]any{"active": true}}, time.Minute)
		c.Invalidate("key-2")
		c.Invalidate("key-2") // second call on an already-evicted key must not panic
		if _, ok := c.Get("key-2"); ok {
			t.Fatal("entry should stay evicted")
		}
	})

	t.Run("other keys are untouched", func(t *testing.T) {
		c := NewMemoryIntrospectionCache()
		c.Set("keep", &oauth.CachedResult{Body: map[string]any{"active": true}}, time.Minute)
		c.Set("evict", &oauth.CachedResult{Body: map[string]any{"active": true}}, time.Minute)
		c.Invalidate("evict")
		if _, ok := c.Get("keep"); !ok {
			t.Fatal("Invalidate must only evict the targeted key, not the whole cache")
		}
	})
}
