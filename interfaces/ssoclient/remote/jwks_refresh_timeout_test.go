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

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
)

// rotatingJWKSServer serves whichever public key is currently stored in kp
// (an atomic.Pointer so the handler and the test can safely race on it)
// under a FIXED kid, letting a test simulate the server rotating the key
// material behind an already-cached kid.
func rotatingJWKSServer(t *testing.T) (url string, kp *atomic.Pointer[ed25519.PublicKey], stop func()) {
	t.Helper()
	kp = &atomic.Pointer[ed25519.PublicKey]{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := kp.Load()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"rotated-kid","x":%q}]}`,
			base64.RawURLEncoding.EncodeToString(*pub))
	})
	srv := httptest.NewServer(mux)
	return srv.URL + "/.well-known/jwks.json", kp, srv.Close
}

// TestJWKSCache_BackgroundRefresh_SurvivesZeroTimeoutClient pins a bug where
// refreshLoop derived its per-tick context via
// context.WithTimeout(ctx, j.client.Timeout): http.Client.Timeout == 0 is
// the documented, legitimate "no client-side timeout" configuration (a
// caller instead bounding each call by its own context, e.g. via
// WithJWKSHTTPClient), but context.WithTimeout(parent, 0) creates an
// ALREADY-EXPIRED context — so every background refresh tick failed before
// the request could complete, silently (the error is discarded by
// refreshLoop), permanently starving the cache of the periodic refresh the
// package doc promises ("Short enough that key rotation propagates
// promptly").
//
// The cache is primed via one on-demand Get, which forwards the CALLER's
// context (unaffected by the bug) — this is deliberate: it puts "rotated-kid"
// in the cache so that a later Get for the SAME kid is answered straight
// from the map (see getJWK's loaded+ok fast path), with no on-demand fetch
// in between. That isolates the assertion to whether the BACKGROUND loop
// alone can still update an already-cached key.
func TestJWKSCache_BackgroundRefresh_SurvivesZeroTimeoutClient(t *testing.T) {
	t.Parallel()
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	url, kp, stop := rotatingJWKSServer(t)
	defer stop()
	kp.Store(&pub1)

	// Timeout: 0 is the exact idiomatic configuration this bug breaks — a
	// caller relying on context deadlines instead of a client-level timeout.
	zeroTimeoutClient := &http.Client{Timeout: 0}

	cache := remote.NewJWKSCache(url,
		remote.WithJWKSHTTPClient(zeroTimeoutClient),
		remote.WithJWKSRefreshInterval(15*time.Millisecond),
	)
	defer cache.Close()

	// Prime the cache via the on-demand path (caller's own context — not
	// touched by the bug), so "rotated-kid" now resolves straight from the
	// map on every subsequent Get.
	got1, err := cache.Get(context.Background(), "rotated-kid")
	if err != nil {
		t.Fatalf("priming Get: %v", err)
	}
	if !pub1.Equal(got1) {
		t.Fatal("priming Get returned the wrong key")
	}

	// Rotate the server's key material under the SAME kid.
	kp.Store(&pub2)

	// Poll (bounded, not a fixed sleep) for the background loop to pick up
	// the rotation. A working loop converges within a handful of 15ms
	// ticks; a broken one (every tick's context already expired) never
	// converges, and the test fails at the deadline.
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, err := cache.Get(context.Background(), "rotated-kid")
		if err != nil {
			t.Fatalf("Get(rotated-kid): %v", err)
		}
		if pub2.Equal(got) {
			return // background refresh picked up the rotation — bug fixed
		}
		if time.Now().After(deadline) {
			t.Fatal("background refresh never picked up the rotated key " +
				"(a Timeout:0 http.Client makes every refreshLoop tick's " +
				"context already-expired, per context.WithTimeout(_, 0))")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
