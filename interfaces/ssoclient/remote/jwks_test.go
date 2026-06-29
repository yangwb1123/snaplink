package remote_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/ssoclient/remote"
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
