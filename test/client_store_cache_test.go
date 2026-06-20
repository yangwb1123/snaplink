package ssotest

import "github.com/snaplink/sso/protocols/oauth"

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// newCachedDCRHarness builds a server with the opt-in per-login ClientStore
// cache AND DCR enabled, so the RFC 7592 management endpoints exercise the
// real (*sso.Server).InvalidateClientCache wiring end-to-end. Returns the
// HTTP server, the raw underlying store, and the *sso.Server (whose
// clientStore is the cache decorator).
func newCachedDCRHarness(t *testing.T, ttl time.Duration) (*httptest.Server, *defaultimpl.MemoryClientStore, *sso.Server) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithClientStoreCache(ttl),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{
			AllowOpenRegistration: true,
			DefaultActive:         true,
			DefaultTokenStrategy:  "jwt",
		}),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, clients, srv
}

// A DCR PUT (RFC 7592 §2.2) must evict the per-login client cache so the
// server's next ClientStore.Get reflects the updated metadata immediately
// rather than after the TTL. Locks the DCR-update -> InvalidateClientCache
// wiring (oauth/handle_register.go HandleRegistrationPut).
func TestClientCache_DCRUpdateEvicts(t *testing.T) {
	httpSrv, _, srv := newCachedDCRHarness(t, time.Hour) // long TTL: only eviction can refresh
	ctx := context.Background()

	id, tok, uri := registerForMgmt(t, httpSrv.URL)

	// Prime the cache via the server's own ClientStore (the path login/token use).
	primed, err := srv.ClientStoreAccessor().Get(ctx, id)
	if err != nil {
		t.Fatalf("prime get: %v", err)
	}
	if primed.Name != "mgmt-test" {
		t.Fatalf("primed name = %q, want mgmt-test", primed.Name)
	}

	// PUT new metadata through the RFC 7592 management endpoint.
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://app.example/cb2"},
		"client_name":   "renamed",
	})
	req, _ := http.NewRequest(http.MethodPut, uri, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put status=%d body=%s", resp.StatusCode, rawBody)
	}

	// The server's next Get must see the new metadata (cache evicted), NOT the
	// stale primed snapshot — despite the hour-long TTL.
	got, err := srv.ClientStoreAccessor().Get(ctx, id)
	if err != nil {
		t.Fatalf("get after PUT: %v", err)
	}
	if got.Name != "renamed" {
		t.Fatalf("name after DCR PUT = %q, want renamed (cache not evicted)", got.Name)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app.example/cb2" {
		t.Fatalf("redirect after DCR PUT = %v, want [https://app.example/cb2]", got.RedirectURIs)
	}
}

// A DCR DELETE (RFC 7592 §2.3) must evict the cache so the deleted client
// reverts to the not-found behavior on the server's next Get immediately.
func TestClientCache_DCRDeleteEvicts(t *testing.T) {
	httpSrv, _, srv := newCachedDCRHarness(t, time.Hour)
	ctx := context.Background()

	id, tok, uri := registerForMgmt(t, httpSrv.URL)
	if _, err := srv.ClientStoreAccessor().Get(ctx, id); err != nil { // prime
		t.Fatalf("prime get: %v", err)
	}

	req, _ := http.NewRequest(http.MethodDelete, uri, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", resp.StatusCode)
	}

	// The deleted client must be unknown on the next Get (not a cached hit).
	if _, err := srv.ClientStoreAccessor().Get(ctx, id); err != sso.ErrNoSuchClient {
		t.Fatalf("get after DCR DELETE = %v, want ErrNoSuchClient (cache not evicted)", err)
	}
}
