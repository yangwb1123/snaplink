package ssotest

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

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// countingClientStore wraps a real store and counts List() + Stats()
// calls so tests can assert the cache amortizes per-request work and
// that the fingerprint fast-path actually fires.
type countingClientStore struct {
	*defaultimpl.MemoryClientStore
	calls      atomic.Int32
	statsCalls atomic.Int32
}

func (c *countingClientStore) List(ctx context.Context) ([]*sso.Client, error) {
	c.calls.Add(1)
	return c.MemoryClientStore.List(ctx)
}

// Stats forwards to the embedded store but counts the call so tests can
// prove the discovery refresh consulted the cheap fingerprint instead
// of re-Listing. (Method promotion alone would satisfy the interface,
// but then we couldn't observe the call.)
func (c *countingClientStore) Stats(ctx context.Context) (int, string, error) {
	c.statsCalls.Add(1)
	return c.MemoryClientStore.Stats(ctx)
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
		_ = resp.Body.Close()
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
		_ = resp.Body.Close()
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

func TestDiscoveryCache_StatsSkipsRecomputeWhenUnchanged(t *testing.T) {
	// Tiny TTL so both the snapshot and doc caches expire between the
	// two requests, forcing the refresh path. The client set never
	// changes, so the second refresh must consult the cheap fingerprint
	// (Stats) and reuse the prior derived fields WITHOUT a second List.
	srv, counter := newDiscoveryCacheHarness(t, time.Millisecond)

	first := fetchDoc(t, srv)
	if counter.calls.Load() != 1 {
		t.Fatalf("warm-up List calls = %d, want 1", counter.calls.Load())
	}

	// Wait well past the TTL so the cached snapshot is stale.
	time.Sleep(25 * time.Millisecond)

	second := fetchDoc(t, srv)

	if got := counter.calls.Load(); got != 1 {
		t.Errorf("List called %d times across a stale refresh, want 1 (fingerprint should skip the recompute)", got)
	}
	if got := counter.statsCalls.Load(); got < 1 {
		t.Errorf("Stats called %d times, want >=1 (cheap fingerprint path must run)", got)
	}
	// The served document must be unchanged — skipping the recompute
	// must not weaken correctness.
	if !equalJSON(first["scopes_supported"], second["scopes_supported"]) {
		t.Errorf("scopes_supported drifted across fingerprint-skip: %v vs %v",
			first["scopes_supported"], second["scopes_supported"])
	}
}

func TestDiscoveryCache_StatsRecomputesWhenScopeChanges(t *testing.T) {
	// When a discovery-relevant field changes (a client's scope), the
	// fingerprint must differ, forcing a fresh List + re-projection so
	// the document reflects the new scope.
	srv, counter := newDiscoveryCacheHarness(t, time.Millisecond)

	first := fetchDoc(t, srv)
	if !containsString(toStringSlice(first["scopes_supported"]), "read") {
		t.Fatalf("seed scope missing from first doc: %v", first["scopes_supported"])
	}
	listsAfterWarmup := counter.calls.Load()

	// Mutate the client set out-of-band (no cache invalidation call) so
	// the ONLY thing that can detect the change is the fingerprint.
	if err := counter.Update(context.Background(),
		&sso.Client{ID: "cc-c", Active: true, AllowedScopes: []string{"read", "newscope"}, RequirePAR: true}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	time.Sleep(25 * time.Millisecond)

	second := fetchDoc(t, srv)
	if got := counter.calls.Load(); got <= listsAfterWarmup {
		t.Errorf("List calls = %d, want > %d (changed fingerprint must trigger recompute)", got, listsAfterWarmup)
	}
	if !containsString(toStringSlice(second["scopes_supported"]), "newscope") {
		t.Errorf("new scope not reflected after fingerprint change: %v", second["scopes_supported"])
	}
}

func toStringSlice(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func fetchDoc(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
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
