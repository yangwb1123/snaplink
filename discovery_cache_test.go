package sso_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// countingClientStore wraps a real store and counts List() calls so
// tests can assert the cache amortizes per-request work.
type countingClientStore struct {
	*defaultimpl.MemoryClientStore
	calls atomic.Int32
}

func (c *countingClientStore) List(ctx context.Context) ([]*sso.Client, error) {
	c.calls.Add(1)
	return c.MemoryClientStore.List(ctx)
}

func newDiscoveryCacheHarness(t *testing.T, ttl time.Duration) (*httptest.Server, *countingClientStore) {
	t.Helper()
	mem := defaultimpl.NewMemoryClientStore()
	mem.AddSeed(&sso.Client{ID: "cc-c", Active: true, AllowedScopes: []string{"read"}, RequirePAR: true})
	counter := &countingClientStore{MemoryClientStore: mem}
	srv := sso.NewServer(
		sso.WithIssuer("https://cache.example"),
		sso.WithClientStore(counter),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(defaultimpl.NewEd25519JWTIssuer()),
		sso.WithPARStore(defaultimpl.NewMemoryPARStore(), time.Minute),
		sso.WithDiscoveryCacheTTL(ttl),
		// Body cache mirrors snapshot cache so "ttl=0 disables
		// caching" tests below see real client-store fan-out.
		sso.WithDiscoveryDocCacheTTL(ttl),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, counter
}

func TestDiscoveryCache_AmortizesListCalls(t *testing.T) {
	srv, counter := newDiscoveryCacheHarness(t, 5*time.Second)

	// Three back-to-back discovery hits within the TTL window should
	// trigger ONE ClientStore.List call (the first one); the next two
	// read from the cached snapshot.
	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d on call %d", resp.StatusCode, i)
		}
	}
	if got := counter.calls.Load(); got != 1 {
		t.Errorf("ClientStore.List was called %d times, want 1 (cache hit on 2nd/3rd request)", got)
	}
}

func TestDiscoveryCache_DisabledWhenTTLZero(t *testing.T) {
	srv, counter := newDiscoveryCacheHarness(t, 0)

	// With caching disabled (TTL=0), every request iterates the store.
	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
	}
	if got := counter.calls.Load(); got != 3 {
		t.Errorf("ClientStore.List was called %d times, want 3 (cache disabled)", got)
	}
}

func TestDiscoveryCache_ProjectionMatchesUncached(t *testing.T) {
	// The cached + uncached paths MUST produce identical discovery
	// docs for the same client store. This guards against the
	// snapshot projection drifting from the live computation.
	cachedSrv, _ := newDiscoveryCacheHarness(t, 5*time.Second)
	uncachedSrv, _ := newDiscoveryCacheHarness(t, 0)

	cachedDoc := fetchDoc(t, cachedSrv)
	uncachedDoc := fetchDoc(t, uncachedSrv)

	// Spot-check the fields that derive from the snapshot.
	for _, k := range []string{
		"scopes_supported",
		"require_pushed_authorization_requests",
		"frontchannel_logout_supported",
	} {
		if !equalJSON(cachedDoc[k], uncachedDoc[k]) {
			t.Errorf("field %q diverges: cached=%v uncached=%v", k, cachedDoc[k], uncachedDoc[k])
		}
	}
}

func fetchDoc(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	return decodeBody(t, resp)
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v body=%s", err, raw)
	}
	return out
}

func equalJSON(a, b any) bool {
	// reflect.DeepEqual handles the nil / slice / bool / float64
	// shapes the discovery doc emits after JSON unmarshal.
	return reflect.DeepEqual(a, b)
}
