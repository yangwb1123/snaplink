package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/shared/core"
)

type ttlObservingCache struct {
	core.IdempotentCache
	ttl time.Duration
}

func (c *ttlObservingCache) Set(ctx context.Context, key string, body []byte, ttl time.Duration) error {
	c.ttl = ttl
	return c.IdempotentCache.Set(ctx, key, body, ttl)
}

func TestCapturedResponseUsesExplicitFiniteTTL(t *testing.T) {
	for _, tc := range []struct {
		body string
		ttl  time.Duration
	}{
		{`{"access_token":"a","expires_in":3600}`, time.Minute},
		{`{"access_token":"a","expires_in":3}`, 3 * time.Second},
		{`{"access_token":"a","expires_in":9223372036854775807}`, time.Minute},
		{`{"access_token":"a","expires_in":0}`, 0},
		{`{"access_token":"a","expires_in":-1}`, 0},
		{`{"result":"ok"}`, time.Minute},
	} {
		t.Run(tc.body, func(t *testing.T) {
			memory := defaultimpl.NewMemoryIdempotentCache(time.Hour)
			defer memory.Close()
			cache := &ttlObservingCache{IdempotentCache: memory}
			ctx := core.NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/token", nil))
			middleware.CommitCapturedBody(ctx, "operation", cache, []byte(tc.body), http.StatusOK)
			_, hit, err := cache.Get(t.Context(), "operation")
			if cache.ttl != tc.ttl || hit != (tc.ttl > 0) || err != nil {
				t.Fatalf("ttl=%v hit=%v err=%v, want ttl=%v", cache.ttl, hit, err, tc.ttl)
			}
		})
	}
}

func TestCapturedResponseNeverCachesErrorsOrEmptyBodies(t *testing.T) {
	memory := defaultimpl.NewMemoryIdempotentCache(time.Hour)
	defer memory.Close()
	ctx := core.NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/token", nil))
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError} {
		middleware.CommitCapturedBody(ctx, "error", memory, []byte(`{"error":"invalid_grant"}`), status)
		if _, hit, _ := memory.Get(t.Context(), "error"); hit {
			t.Fatalf("cached status %d", status)
		}
	}
	middleware.CommitCapturedBody(ctx, "empty", memory, nil, http.StatusOK)
	if _, hit, _ := memory.Get(t.Context(), "empty"); hit {
		t.Fatal("cached an empty response")
	}
}
