package ssotest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// newAuthzBundleHarness builds an SSO server with a permissions provider
// (so the policy-bundle route mounts) and a client store (so unknown-client
// 404 works), then wraps the handler in AdminMiddleware exactly as cmd does
// (base = adminMW.HTTPMiddleware(base)) so the /api/v1/admin/ path is
// gated as admin:read. user-alice has admin:* under client "" (the bundle's
// admin scope is checked against the token's client_id, here empty).
func newAuthzBundleHarness(t *testing.T, prov permissions.Provider, ttl time.Duration) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "web-app", Secret: "s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithPermissionProvider(prov),
		sso.WithAuthzPolicyBundleCacheTTL(ttl),
	)
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-alice"}}, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// seededBundleProvider gives user-alice admin:* (admin scope) and defines
// two roles under "web-app" so the bundle has content.
func seededBundleProvider(t *testing.T) permissions.Provider {
	t.Helper()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = p.AssignRoles(ctx, "user-alice", "", []string{"root"})
	_ = p.AddRole(ctx, "web-app", permissions.Role{Code: "admin", Permissions: []string{"user:*", "order:*"}})
	_ = p.AddRole(ctx, "web-app", permissions.Role{Code: "viewer", Permissions: []string{"user:read"}})
	return p
}

const bundlePath = "/api/v1/admin/authz/policy-bundle"

func TestAuthzPolicyBundle_OKWithETagAndCacheControl(t *testing.T) {
	srv := newAuthzBundleHarness(t, seededBundleProvider(t), time.Minute)
	resp := httpDo(t, "GET", srv.URL+bundlePath+"?client_id=web-app", "good")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if etag := resp.Header.Get("ETag"); etag == "" || !strings.HasPrefix(etag, `"`) {
		t.Fatalf("ETag=%q want non-empty quoted strong validator", etag)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=") {
		t.Fatalf("Cache-Control=%q want public max-age (NOT no-store)", cc)
	}
	// Body carries the role definitions + static semantics.
	var b permissions.PolicyBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(b.Roles) != 2 || b.Roles[0].Code != "admin" {
		t.Fatalf("bundle roles = %+v", b.Roles)
	}
	if b.WildcardSemantics.AllToken != "*" {
		t.Fatalf("missing wildcard semantics: %+v", b.WildcardSemantics)
	}
}

func TestAuthzPolicyBundle_IfNoneMatch304(t *testing.T) {
	srv := newAuthzBundleHarness(t, seededBundleProvider(t), time.Minute)
	first := httpDo(t, "GET", srv.URL+bundlePath+"?client_id=web-app", "good")
	_ = first.Body.Close()
	etag := first.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on first response")
	}
	req, _ := http.NewRequest("GET", srv.URL+bundlePath+"?client_id=web-app", nil)
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("If-None-Match", etag)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304", resp.StatusCode)
	}
}

func TestAuthzPolicyBundle_MissingClientID400(t *testing.T) {
	srv := newAuthzBundleHarness(t, seededBundleProvider(t), time.Minute)
	resp := httpDo(t, "GET", srv.URL+bundlePath, "good")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "missing_client_id" {
		t.Fatalf("error=%q want missing_client_id", body["error"])
	}
}

func TestAuthzPolicyBundle_UnknownClient404(t *testing.T) {
	srv := newAuthzBundleHarness(t, seededBundleProvider(t), time.Minute)
	resp := httpDo(t, "GET", srv.URL+bundlePath+"?client_id=nope", "good")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d want 404", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "client_not_found" {
		t.Fatalf("error=%q want client_not_found", body["error"])
	}
}

func TestAuthzPolicyBundle_MissingTokenIs401(t *testing.T) {
	srv := newAuthzBundleHarness(t, seededBundleProvider(t), time.Minute)
	resp := httpDo(t, "GET", srv.URL+bundlePath+"?client_id=web-app", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
}

func TestAuthzPolicyBundle_InsufficientScopeIs403(t *testing.T) {
	// user-bob has no admin scope: provider grants only items:read.
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.AddRole(ctx, "", permissions.Role{Code: "user", Permissions: []string{"items:read"}})
	_ = p.AssignRoles(ctx, "user-bob", "", []string{"user"})
	_ = p.AddRole(ctx, "web-app", permissions.Role{Code: "viewer", Permissions: []string{"user:read"}})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "web-app", Secret: "s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithPermissionProvider(p),
	)
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-bob"}}, p)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	resp := httpDo(t, "GET", httpSrv.URL+bundlePath+"?client_id=web-app", "good")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want 403", resp.StatusCode)
	}
}

// TestAuthzPolicyBundle_MutationInvalidatesCache: a role edit followed by
// InvalidateAuthzPolicyBundleCache (the hook cmd wires to the admin role
// mutations) must change the served ETag — proving the local cache was
// dropped and the bundle re-rendered from current role state.
func TestAuthzPolicyBundle_MutationInvalidatesCache(t *testing.T) {
	prov := seededBundleProvider(t)
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "web-app", Secret: "s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithPermissionProvider(prov),
		sso.WithAuthzPolicyBundleCacheTTL(time.Hour), // long TTL: only invalidation should bust it
	)
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-alice"}}, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	first := httpDo(t, "GET", httpSrv.URL+bundlePath+"?client_id=web-app", "good")
	_ = first.Body.Close()
	etag1 := first.Header.Get("ETag")
	if etag1 == "" {
		t.Fatal("no ETag on first response")
	}

	// Edit a role's permissions, then fire the invalidation hook (what the
	// gRPC PermissionAdminService callback does on a successful mutation).
	if err := prov.UpdateRole(context.Background(), "web-app", permissions.Role{
		Code: "viewer", Permissions: []string{"user:read", "report:read"},
	}); err != nil {
		t.Fatalf("update role: %v", err)
	}
	srv.InvalidateAuthzPolicyBundleCache("web-app")

	second := httpDo(t, "GET", httpSrv.URL+bundlePath+"?client_id=web-app", "good")
	_ = second.Body.Close()
	etag2 := second.Header.Get("ETag")
	if etag2 == etag1 {
		t.Fatalf("ETag unchanged after role edit + invalidation: %q (cache not busted)", etag2)
	}
}
