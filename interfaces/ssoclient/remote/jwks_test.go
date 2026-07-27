package remote_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
)

// jwksServer constructs a test JWKS endpoint that exposes the given keypair
// under the kid "test-kid". The hitCounter tracks how many times JWKS was
// fetched so tests can verify caching behavior.
func jwksServer(t *testing.T, pub ed25519.PublicKey) (string, *atomic.Int64, func()) {
	t.Helper()
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test-kid","x":%q}]}`,
			base64.RawURLEncoding.EncodeToString(pub))
	})
	srv := httptest.NewServer(mux)
	return srv.URL + "/.well-known/jwks.json", &hits, srv.Close
}

func TestJWKSCache_GetFetchesOnFirstCallAndCachesAfter(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	url, hits, stop := jwksServer(t, pub)
	defer stop()

	cache := remote.NewJWKSCache(url)
	defer cache.Close()

	for range 5 {
		got, err := cache.Get(context.Background(), "test-kid")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !pub.Equal(got) {
			t.Fatalf("returned key does not match published key")
		}
	}
	// After first miss, the cache holds the key; subsequent Gets are
	// hash-map lookups.
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 JWKS fetch, got %d", got)
	}
}

func TestJWKSCache_GetUnknownKidTriggersRefetch(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	url, hits, stop := jwksServer(t, pub)
	defer stop()

	// NewJWKSCache with a 1ns forced-fetch interval so the debounce window
	// expires immediately and the re-fetch is not suppressed.
	cache := remote.NewJWKSCache(url, remote.WithJWKSForcedFetchInterval(time.Nanosecond))
	defer cache.Close()

	// Prime cache.
	_, _ = cache.Get(context.Background(), "test-kid")
	if hits.Load() != 1 {
		t.Fatalf("priming hit count = %d, want 1", hits.Load())
	}

	// Unknown kid → re-fetch (still won't find it in this test server, but
	// the re-fetch attempt itself is the observable behavior).
	_, err := cache.Get(context.Background(), "rotated-kid")
	if err == nil {
		t.Fatal("expected error for unknown kid after refetch")
	}
	if hits.Load() != 2 {
		t.Fatalf("expected refetch on unknown kid; hit count = %d", hits.Load())
	}
}

func TestJWKSCache_DebounceBlocksImmediateRefetch(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	url, hits, stop := jwksServer(t, pub)
	defer stop()

	cache := remote.NewJWKSCache(url)
	defer cache.Close()

	// Prime cache — first load unconditionally fetches.
	_, _ = cache.Get(context.Background(), "test-kid")
	if hits.Load() != 1 {
		t.Fatalf("priming hit count = %d, want 1", hits.Load())
	}

	// Within the debounce window, unknown kid returns an error WITHOUT
	// an upstream fetch — prevents amplification from attacker-controlled kids.
	_, err := cache.Get(context.Background(), "rotated-kid")
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
	if hits.Load() != 1 {
		t.Fatalf("debounce should prevent refetch; hit count = %d, want 1", hits.Load())
	}
}

func TestJWKSCache_BadStatusReturnsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cache := remote.NewJWKSCache(srv.URL + "/.well-known/jwks.json")
	defer cache.Close()
	if _, err := cache.Get(context.Background(), "x"); err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestJWKSCache_NoUsableKeysIsAnError(t *testing.T) {
	t.Parallel()
	// Returns a doc with only an unsupported key type — should fail rather
	// than silently cache an empty key map.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"keys":[{"kty":"RSA","kid":"r1","n":"x","e":"AQAB"}]}`)
	}))
	defer srv.Close()

	cache := remote.NewJWKSCache(srv.URL + "/.well-known/jwks.json")
	defer cache.Close()
	if _, err := cache.Get(context.Background(), "r1"); err == nil {
		t.Fatal("expected error when no Ed25519 keys present")
	}
}

func TestJWKSCache_ClosedoesNotPanic(t *testing.T) {
	t.Parallel()
	cache := remote.NewJWKSCache("http://does-not-matter",
		remote.WithJWKSRefreshInterval(time.Hour),
	)
	cache.Close()
	cache.Close() // idempotent
}

// TestJWKSCache_ETagRevalidationSkipsBody proves an unrotated JWKS costs the
// caller a 304 with no body: the cache sends back the validator from the
// last 200, and a 304 response must leave the previously cached keys intact
// rather than stranding the cache empty.
func TestJWKSCache_ETagRevalidationSkipsBody(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var hits, notModified atomic.Int64
	const etag = `"etag-1"`
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == etag {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test-kid","x":%q}]}`,
			base64.RawURLEncoding.EncodeToString(pub))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cache := remote.NewJWKSCache(srv.URL+"/.well-known/jwks.json", remote.WithJWKSForcedFetchInterval(time.Nanosecond))
	defer cache.Close()

	if _, err := cache.Get(context.Background(), "test-kid"); err != nil {
		t.Fatalf("prime Get: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("priming hits = %d, want 1", hits.Load())
	}

	// An unknown kid forces another on-demand fetch; the server must answer
	// 304 because the cache now holds and resends the ETag.
	_, _ = cache.Get(context.Background(), "unknown-kid")
	if hits.Load() != 2 {
		t.Fatalf("hits after second fetch = %d, want 2", hits.Load())
	}
	if notModified.Load() != 1 {
		t.Fatalf("notModified = %d, want 1 (If-None-Match should have matched)", notModified.Load())
	}
	// The 304 must not have emptied the cache: the original key still resolves.
	if _, err := cache.Get(context.Background(), "test-kid"); err != nil {
		t.Fatalf("Get after 304: %v", err)
	}
}

// TestJWKSCache_StartRefresherClosesOnContextCancel proves the optional
// context-lifecycle hook tears the background refresh loop down exactly like
// an explicit Close — and that a caller's own Close racing with it is still
// safe (sync.Once, not a double-close panic).
func TestJWKSCache_StartRefresherClosesOnContextCancel(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	var startedOnce, canceledOnce sync.Once
	requestStarted := make(chan struct{})
	requestCanceled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		startedOnce.Do(func() { close(requestStarted) })
		<-r.Context().Done()
		canceledOnce.Do(func() { close(requestCanceled) })
	}))
	defer srv.Close()

	cache := remote.NewJWKSCache(srv.URL, remote.WithJWKSRefreshInterval(time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	cache.StartRefresher(ctx)

	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("background JWKS refresh did not start")
	}
	cancel()

	select {
	case <-requestCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation did not cancel the in-flight JWKS refresh")
	}

	closed := make(chan struct{})
	go func() {
		cache.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wait for the background refresher to stop")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("background refresh count = %d, want 1", got)
	}
	cache.Close() // remains idempotent after the context-triggered close
}

// TestJWKSCache_ConcurrentGetIsRaceFree drives Get from many goroutines
// against both a known and a rotating-unknown kid while the background
// refresher is also ticking, so `go test -race` exercises the cache's
// locking (mu around keys/etag/loaded/lastForcedFetch) under real
// contention rather than only the single-goroutine call patterns above.
func TestJWKSCache_ConcurrentGetIsRaceFree(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	url, _, stop := jwksServer(t, pub)
	defer stop()

	cache := remote.NewJWKSCache(url,
		remote.WithJWKSRefreshInterval(2*time.Millisecond),
		remote.WithJWKSForcedFetchInterval(time.Millisecond),
	)
	defer cache.Close()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				kid := "test-kid"
				if j%2 == 0 {
					kid = fmt.Sprintf("unknown-%d-%d", i, j)
				}
				_, _ = cache.Get(context.Background(), kid)
				_, _ = cache.GetJWK(context.Background(), kid)
			}
		}(i)
	}
	wg.Wait()
}
