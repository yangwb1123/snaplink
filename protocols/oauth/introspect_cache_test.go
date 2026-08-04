package oauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// fakeInvalidatingCache is a minimal IntrospectionCache that ALSO implements
// IntrospectionCacheInvalidator, so tests can assert InvalidateIntrospectionCache
// computes the SAME key derivation (SHA-256(token) hex, per tokenHash) that
// introspectOne uses to populate the cache in the first place.
type fakeInvalidatingCache struct {
	entries        map[string]*CachedResult
	invalidatedKey string
	invalidateN    int
}

func newFakeInvalidatingCache() *fakeInvalidatingCache {
	return &fakeInvalidatingCache{entries: map[string]*CachedResult{}}
}

func (f *fakeInvalidatingCache) Get(key string) (*CachedResult, bool) {
	r, ok := f.entries[key]
	return r, ok
}

func (f *fakeInvalidatingCache) Set(key string, result *CachedResult, _ time.Duration) {
	f.entries[key] = result
}

func (f *fakeInvalidatingCache) Invalidate(key string) {
	f.invalidatedKey = key
	f.invalidateN++
	delete(f.entries, key)
}

var (
	_ IntrospectionCache            = (*fakeInvalidatingCache)(nil)
	_ IntrospectionCacheInvalidator = (*fakeInvalidatingCache)(nil)
)

// fakeNonInvalidatingCache implements ONLY the base IntrospectionCache — no
// Invalidate — modeling a third-party backend that predates the extension.
type fakeNonInvalidatingCache struct {
	entries map[string]*CachedResult
}

func (f *fakeNonInvalidatingCache) Get(key string) (*CachedResult, bool) {
	r, ok := f.entries[key]
	return r, ok
}
func (f *fakeNonInvalidatingCache) Set(key string, result *CachedResult, _ time.Duration) {
	if f.entries == nil {
		f.entries = map[string]*CachedResult{}
	}
	f.entries[key] = result
}

var _ IntrospectionCache = (*fakeNonInvalidatingCache)(nil)

func TestIntrospectionCacheMissValidatesAccessTokenOnce(t *testing.T) {
	t.Parallel()
	d := newIntrospectDeps(newMemClientStore(), newMemRefreshStore())
	cache := newFakeInvalidatingCache()
	d.introspectionCache, d.cacheTTL = cache, time.Minute
	validations := 0
	d.validate = func(context.Context, string) (*core.TokenClaims, string, error) {
		validations++
		return &core.TokenClaims{
			TokenUse: core.TokenUseAccessToken,
			Subject:  "service",
			Actor:    &core.ActorClaim{Subject: "human"},
		}, "jwt", nil
	}
	ctx, _ := newCtx(http.MethodPost, core.ContentTypeJSON, "")
	for range 2 {
		if body := introspectOne(d, ctx, "access-token", ""); body[core.KeyActive] != true {
			t.Fatalf("introspection body = %v, want active", body)
		}
	}
	if validations != 1 {
		t.Fatalf("ValidateAnyToken calls = %d, want one cache-miss validation", validations)
	}
	cached, ok := cache.Get(tokenHash("access-token"))
	if !ok || len(cached.LifecycleSubjects) != 2 || cached.LifecycleSubjects[1] != "human" {
		t.Fatalf("cached lifecycle subjects = %#v, want sub plus actor", cached)
	}
}

func TestInvalidateIntrospectionCache(t *testing.T) {
	t.Parallel()

	t.Run("evicts the SAME key introspectOne would have populated", func(t *testing.T) {
		cache := newFakeInvalidatingCache()
		token := "opaque-bearer-token"
		wantKey := tokenHash(token)
		cache.Set(wantKey, &CachedResult{Body: map[string]any{"active": true}}, time.Minute)

		InvalidateIntrospectionCache(cache, token)

		if cache.invalidatedKey != wantKey {
			t.Fatalf("invalidated key = %q, want %q (must match tokenHash used by introspectOne)", cache.invalidatedKey, wantKey)
		}
		if _, ok := cache.Get(wantKey); ok {
			t.Fatal("entry survived invalidation")
		}
	})

	t.Run("nil cache is a safe no-op", func(t *testing.T) {
		// Must not panic — this is the default (unwired) case for every
		// revocation call site that doesn't configure WithIntrospectionCache.
		InvalidateIntrospectionCache(nil, "any-token")
	})

	t.Run("empty token is a safe no-op", func(t *testing.T) {
		cache := newFakeInvalidatingCache()
		InvalidateIntrospectionCache(cache, "")
		if cache.invalidateN != 0 {
			t.Fatalf("Invalidate called %d times for an empty token, want 0", cache.invalidateN)
		}
	})

	t.Run("cache without the optional extension degrades to a no-op, never panics", func(t *testing.T) {
		cache := &fakeNonInvalidatingCache{}
		token := "tok"
		cache.Set(tokenHash(token), &CachedResult{Body: map[string]any{"active": true}}, time.Minute)

		InvalidateIntrospectionCache(cache, token) // must not panic despite no Invalidate method

		// The entry is still there — TTL-bounded staleness is the documented
		// degrade-gracefully behavior for a backend that predates the extension.
		if _, ok := cache.Get(tokenHash(token)); !ok {
			t.Fatal("entry should remain cached — a non-invalidating backend has no eviction primitive")
		}
	})
}
