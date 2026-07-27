package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/handler"
)

// TestIntrospectionCacheInvalidation is the end-to-end regression guard for the
// gap described in AGENTS.md-adjacent design notes: WithIntrospectionCache
// trades immediate revocation propagation for CPU savings, caching BOTH
// active and inactive /token/introspect results for DefaultIntrospectionCacheTTL
// (or the configured TTL). Without point-eviction, a token revoked via
// /token/revoke, /logout, or a refresh-family-reuse kill keeps reporting a
// STALE active:true to any relying party that introspects it again before
// the TTL naturally expires — a real, if time-bounded, oracle problem (a
// resource server is told a just-revoked token is still valid).
//
// Every sub-test below wires a LONG TTL (10 minutes) specifically so a stale
// cache hit would be unmistakable if the revocation path's best-effort
// InvalidateIntrospectionCache call were missing or wrong: any active:true
// after revoke can only be explained by a stale cache entry surviving past
// the point it should have been evicted.
const (
	icaUser   = "u-ica"
	icaClient = "ica-client"
	icaSecret = "ica-secret"
)

func newIntrospectionCacheServer(t *testing.T, cache *handler.MemoryIntrospectionCache) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: icaUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: icaClient, Secret: icaSecret,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: icaUser}, nil
		},
	))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	}
	if cache != nil {
		// A long TTL: if invalidation didn't fire, the stale entry would
		// still be well within its window at test-run speed.
		opts = append(opts, sso.WithIntrospectionCache(cache, 10*time.Minute))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func icaLogin(t *testing.T, srv *httptest.Server) (access, refresh string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  icaClient,
		"credential": map[string]string{"username": "x", "password": "y"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	access, _ = out["access_token"].(string)
	refresh, _ = out["refresh_token"].(string)
	return access, refresh
}

func icaIntrospect(t *testing.T, srv *httptest.Server, token, hint string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"token": token, "token_type_hint": hint,
		"client_id": icaClient, "client_secret": icaSecret,
	})
	resp, err := http.Post(srv.URL+"/token/introspect", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func icaRevoke(t *testing.T, srv *httptest.Server, token, hint string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"token": token, "token_type_hint": hint,
		"client_id": icaClient, "client_secret": icaSecret,
	})
	resp, err := http.Post(srv.URL+"/token/revoke", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func icaLogout(t *testing.T, srv *httptest.Server, bearer string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/logout", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestIntrospectionCacheInvalidation_TokenRevoke proves /token/revoke evicts
// the just-cached introspection result for the SAME (access) token
// immediately, rather than the caller observing a stale active:true for the
// rest of the (long, 10-minute) TTL.
func TestIntrospectionCacheInvalidation_TokenRevoke(t *testing.T) {
	srv := newIntrospectionCacheServer(t, handler.NewMemoryIntrospectionCache())
	access, _ := icaLogin(t, srv)

	// Populate the cache with an active:true result.
	status, body := icaIntrospect(t, srv, access, "access_token")
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("precondition: introspect = %d %v, want 200 active:true", status, body)
	}

	if status := icaRevoke(t, srv, access, "access_token"); status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", status)
	}

	// Without cache invalidation this would return the STALE cached
	// active:true — the regression this change closes.
	status, body = icaIntrospect(t, srv, access, "access_token")
	if status != http.StatusOK {
		t.Fatalf("post-revoke introspect status = %d, want 200", status)
	}
	if body["active"] != false {
		t.Fatalf("post-revoke introspect active = %v, want false (stale cache entry was not invalidated)", body["active"])
	}
}

// TestIntrospectionCacheInvalidation_RefreshTokenRevoke mirrors the access
// token case for the refresh-token tier, which shares the SAME cache (keyed
// by the raw presented token regardless of type).
func TestIntrospectionCacheInvalidation_RefreshTokenRevoke(t *testing.T) {
	srv := newIntrospectionCacheServer(t, handler.NewMemoryIntrospectionCache())
	_, refresh := icaLogin(t, srv)

	status, body := icaIntrospect(t, srv, refresh, "refresh_token")
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("precondition: introspect = %d %v, want 200 active:true", status, body)
	}

	if status := icaRevoke(t, srv, refresh, "refresh_token"); status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", status)
	}

	status, body = icaIntrospect(t, srv, refresh, "refresh_token")
	if status != http.StatusOK {
		t.Fatalf("post-revoke introspect status = %d, want 200", status)
	}
	if body["active"] != false {
		t.Fatalf("post-revoke introspect active = %v, want false (stale cache entry was not invalidated)", body["active"])
	}
}

// TestIntrospectionCacheInvalidation_Logout proves POST /logout — which
// revokes the presented bearer via the SAME s.revokeAcrossIssuers choke
// point /token/revoke uses — also closes the cache window immediately.
func TestIntrospectionCacheInvalidation_Logout(t *testing.T) {
	srv := newIntrospectionCacheServer(t, handler.NewMemoryIntrospectionCache())
	access, _ := icaLogin(t, srv)

	status, body := icaIntrospect(t, srv, access, "access_token")
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("precondition: introspect = %d %v, want 200 active:true", status, body)
	}

	if status := icaLogout(t, srv, access); status != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", status)
	}

	status, body = icaIntrospect(t, srv, access, "access_token")
	if status != http.StatusOK {
		t.Fatalf("post-logout introspect status = %d, want 200", status)
	}
	if body["active"] != false {
		t.Fatalf("post-logout introspect active = %v, want false (stale cache entry was not invalidated)", body["active"])
	}
}

// TestIntrospectionCacheInvalidation_Unwired proves the byte-identical
// contract: with NO IntrospectionCache wired (the default), revoke ->
// introspect behaves exactly as it always has (inactive), and the
// InvalidateIntrospectionCache no-op path never panics or otherwise
// perturbs the response.
func TestIntrospectionCacheInvalidation_Unwired(t *testing.T) {
	srv := newIntrospectionCacheServer(t, nil) // no WithIntrospectionCache
	access, _ := icaLogin(t, srv)

	status, body := icaIntrospect(t, srv, access, "access_token")
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("precondition: introspect = %d %v, want 200 active:true", status, body)
	}

	if status := icaRevoke(t, srv, access, "access_token"); status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", status)
	}

	status, body = icaIntrospect(t, srv, access, "access_token")
	if status != http.StatusOK || body["active"] != false {
		t.Fatalf("post-revoke introspect = %d %v, want 200 active:false", status, body)
	}
}

// TestIntrospectionCacheInvalidation_RefreshFamilyReuse proves the
// refresh-family-reuse kill path (OAuth Security BCP §4.13) also evicts the
// replayed leaf's cached introspection result — the DeleteFamily call this
// wires alongside is exactly the "attacker's sibling tokens must stop
// reporting active" security action AGENTS.md's Fail Modes table calls a
// FAIL-CLOSED, not a fail-open, correctness gate.
func TestIntrospectionCacheInvalidation_RefreshFamilyReuse(t *testing.T) {
	srv := newIntrospectionCacheServer(t, handler.NewMemoryIntrospectionCache())
	_, refresh1 := icaLogin(t, srv)

	// Populate the cache for the leaf that is about to be rotated away.
	status, body := icaIntrospect(t, srv, refresh1, "refresh_token")
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("precondition: introspect = %d %v, want 200 active:true", status, body)
	}

	// Legitimate rotation consumes refresh1.
	form := url.Values{
		"grant_type": {"refresh_token"}, "client_id": {icaClient},
		"client_secret": {icaSecret}, "refresh_token": {refresh1},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotation status = %d, want 200", resp.StatusCode)
	}

	// Replay refresh1 (the consumed leaf) — the reuse signal that kills the
	// whole family (OAuth Security BCP §4.13).
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400 invalid_grant", resp2.StatusCode)
	}

	// The replayed leaf's cached introspection result must no longer report
	// active:true — without the fix this would still hit the stale cache
	// entry populated above.
	status, body = icaIntrospect(t, srv, refresh1, "refresh_token")
	if status != http.StatusOK {
		t.Fatalf("post-reuse introspect status = %d, want 200", status)
	}
	if body["active"] != false {
		t.Fatalf("post-reuse introspect active = %v, want false (stale cache entry was not invalidated)", body["active"])
	}
}
