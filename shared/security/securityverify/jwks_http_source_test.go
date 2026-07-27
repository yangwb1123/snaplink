package securityverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// jwksHitServer serves keys and counts requests, so tests can assert whether
// the cache actually skipped a re-fetch.
func jwksHitServer(t *testing.T, keys ...core.JWK) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestHTTPJWKSSource_CachesWithinTTL(t *testing.T) {
	t.Parallel()
	_, jwk := genWITestKey(t, "k1")
	srv, hits := jwksHitServer(t, jwk)

	src := NewHTTPJWKSSource(srv.URL, WithJWKSCacheTTL(time.Hour))
	for i := 0; i < 5; i++ {
		if _, err := src.GetJWKS(context.Background()); err != nil {
			t.Fatalf("GetJWKS #%d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("server hits = %d, want 1 (cache should have skipped the other 4)", got)
	}
}

func TestHTTPJWKSSource_RefetchesAfterTTLExpiry(t *testing.T) {
	t.Parallel()
	_, jwk := genWITestKey(t, "k1")
	srv, hits := jwksHitServer(t, jwk)

	src := NewHTTPJWKSSource(srv.URL, WithJWKSCacheTTL(time.Hour))
	if _, err := src.GetJWKS(context.Background()); err != nil {
		t.Fatalf("first GetJWKS: %v", err)
	}

	// Age the cache past its TTL directly (white-box, same package) instead
	// of sleeping — deterministic and fast.
	src.mu.Lock()
	src.fetchedAt = time.Now().Add(-2 * time.Hour)
	src.mu.Unlock()

	if _, err := src.GetJWKS(context.Background()); err != nil {
		t.Fatalf("second GetJWKS: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Errorf("server hits = %d, want 2 (TTL expiry should trigger exactly one refetch)", got)
	}
}

func TestHTTPJWKSSource_StaleFallbackOnFetchError(t *testing.T) {
	t.Parallel()
	_, jwk := genWITestKey(t, "k1")
	var fail int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.LoadInt32(&fail) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []core.JWK{jwk}})
	}))
	t.Cleanup(srv.Close)

	src := NewHTTPJWKSSource(srv.URL, WithJWKSCacheTTL(time.Millisecond), WithJWKSMaxStaleAge(time.Hour))
	if _, err := src.GetJWKS(context.Background()); err != nil {
		t.Fatalf("first GetJWKS: %v", err)
	}

	// Push the cache past its TTL (so a refetch is attempted) but keep it
	// well inside maxStaleAge, then break the endpoint.
	src.mu.Lock()
	src.fetchedAt = time.Now().Add(-time.Second)
	src.mu.Unlock()
	atomic.StoreInt32(&fail, 1)

	keys, err := src.GetJWKS(context.Background())
	if err != nil {
		t.Fatalf("expected a stale-cache fallback, got error: %v", err)
	}
	if len(keys) != 1 || keys[0].Kid != "k1" {
		t.Errorf("stale fallback returned unexpected keys: %+v", keys)
	}
}

func TestHTTPJWKSSource_FailsClosedWithNoUsableCache(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	src := NewHTTPJWKSSource(srv.URL)
	// No prior successful fetch => nothing to fall back to => fails closed.
	if _, err := src.GetJWKS(context.Background()); err == nil {
		t.Fatal("expected an error with a failing endpoint and no cache")
	}
}

func TestHTTPJWKSSource_StaleBeyondMaxAgeFailsClosed(t *testing.T) {
	t.Parallel()
	_, jwk := genWITestKey(t, "k1")
	var fail int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.LoadInt32(&fail) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []core.JWK{jwk}})
	}))
	t.Cleanup(srv.Close)

	src := NewHTTPJWKSSource(srv.URL, WithJWKSCacheTTL(time.Millisecond), WithJWKSMaxStaleAge(time.Minute))
	if _, err := src.GetJWKS(context.Background()); err != nil {
		t.Fatalf("first GetJWKS: %v", err)
	}

	// Age the cache PAST maxStaleAge too, then break the endpoint — no
	// fallback should be offered; a permanently-down endpoint must
	// eventually fail closed rather than trust a key set forever.
	src.mu.Lock()
	src.fetchedAt = time.Now().Add(-time.Hour)
	src.mu.Unlock()
	atomic.StoreInt32(&fail, 1)

	if _, err := src.GetJWKS(context.Background()); err == nil {
		t.Fatal("expected fail-closed once the cache exceeds maxStaleAge")
	}
}

func TestHTTPJWKSSource_EmptyKeysRejected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []core.JWK{}})
	}))
	t.Cleanup(srv.Close)

	src := NewHTTPJWKSSource(srv.URL)
	if _, err := src.GetJWKS(context.Background()); err == nil {
		t.Fatal("expected an error for an empty keys array")
	}
}

func TestHTTPJWKSSource_NonOKStatusRejected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	src := NewHTTPJWKSSource(srv.URL)
	if _, err := src.GetJWKS(context.Background()); err == nil {
		t.Fatal("expected an error for a non-200 JWKS endpoint response")
	}
}
