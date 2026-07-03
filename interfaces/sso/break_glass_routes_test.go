package sso_test

// break_glass_routes_test.go drives the break-glass admin-session endpoints
// through the real router + AdminMiddleware (not just the interfaces/admin
// package's unit tests), proving the routes are actually mounted, gated, and
// wired to the right stores end to end. Reuses rcovPostJSON/rcovDo from
// rootcov_flow_test.go.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/snaplink/sso/interfaces/sso"
)

const (
	bgRoutesClient = "bg-routes-client"
	bgRoutesSecret = "bg-routes-secret"
	bgAdminAUser   = "bg-admin-a"
	bgAdminBUser   = "bg-admin-b"
)

// bgRoutesPasswordAuth accepts two fixed admin identities so the two-person
// approval rule can be exercised with real bearer tokens from two DIFFERENT
// logged-in admins, not just two literal actor strings.
func bgRoutesPasswordAuth() sso.Authenticator {
	return authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			switch {
			case u == "admin-a" && p == "pw-a":
				return &sso.AuthResult{UserID: bgAdminAUser, AuthMethods: []string{"pwd"}}, nil
			case u == "admin-b" && p == "pw-b":
				return &sso.AuthResult{UserID: bgAdminBUser, AuthMethods: []string{"pwd"}}, nil
			}
			return nil, errors.New("bad credentials")
		},
	))
}

// bgRoutesNewServer wires a server with a real MemoryBreakGlassStore + a real
// MemorySessionManager behind AdminMiddleware, and returns bearer tokens for
// two DIFFERENT admin identities (both admin:*).
func bgRoutesNewServer(t *testing.T) (baseURL, tokenA, tokenB string) {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: bgAdminAUser})
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: bgAdminBUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: bgRoutesClient, Secret: bgRoutesSecret, Name: "Break-Glass Test Client",
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
	})

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, bgAdminAUser, "", []string{"root"})
	_ = prov.AssignRoles(ctx, bgAdminBUser, "", []string{"root"})
	_ = prov.AddRole(ctx, bgRoutesClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, bgAdminAUser, bgRoutesClient, []string{"root"})
	_ = prov.AssignRoles(ctx, bgAdminBUser, bgRoutesClient, []string{"root"})

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(bgRoutesPasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithBreakGlassStore(memorystoreidentity.NewMemoryBreakGlassStore()),
	)

	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	tokenA = bgRoutesLogin(t, httpSrv.URL, "admin-a", "pw-a")
	tokenB = bgRoutesLogin(t, httpSrv.URL, "admin-b", "pw-b")
	return httpSrv.URL, tokenA, tokenB
}

func bgRoutesLogin(t *testing.T, baseURL, username, password string) string {
	t.Helper()
	status, out := rcovPostJSON(t, baseURL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  bgRoutesClient,
		"credential": map[string]string{"username": username, "password": password},
	})
	if status != http.StatusOK {
		t.Fatalf("login(%s) status=%d body=%v", username, status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("login(%s): no access_token in %v", username, out)
	}
	return token
}

// TestBreakGlassRoutes_Gate proves the routes are mounted and reject
// unauthenticated callers, same as every other /api/v1/admin/* endpoint.
func TestBreakGlassRoutes_Gate(t *testing.T) {
	baseURL, _, _ := bgRoutesNewServer(t)
	status, _ := rcovPostJSON(t, baseURL+"/api/v1/admin/break-glass", "", map[string]any{
		"target_user_id": "user-1", "reason": "ticket-1",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated create status = %d, want 401", status)
	}
}

// TestBreakGlassRoutes_FullLifecycle drives create(require_approval) ->
// self-approval rejected -> approved by a DIFFERENT admin -> list -> revoke,
// entirely over real HTTP through AdminMiddleware.
func TestBreakGlassRoutes_FullLifecycle(t *testing.T) {
	baseURL, tokenA, tokenB := bgRoutesNewServer(t)

	status, created := rcovPostJSON(t, baseURL+"/api/v1/admin/break-glass", tokenA, map[string]any{
		"target_user_id":   "user-1",
		"reason":           "ticket-999",
		"scope":            "impersonate",
		"require_approval": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create status = %d body=%v", status, created)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create response missing id: %v", created)
	}
	if created["status"] != "pending" {
		t.Fatalf("status = %v, want pending", created["status"])
	}

	// Self-approval by the SAME admin must be rejected.
	status, errBody := rcovDo(t, http.MethodPost, baseURL+"/api/v1/admin/break-glass/"+id+"/approve", tokenA, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("self-approve status = %d body=%v", status, errBody)
	}
	if errBody["error"] != "break_glass_self_approval" {
		t.Fatalf("self-approve error = %v, want break_glass_self_approval", errBody["error"])
	}

	// A DIFFERENT admin approves successfully.
	status, approved := rcovDo(t, http.MethodPost, baseURL+"/api/v1/admin/break-glass/"+id+"/approve", tokenB, nil)
	if status != http.StatusOK {
		t.Fatalf("approve status = %d body=%v", status, approved)
	}
	if approved["status"] != "active" {
		t.Fatalf("status = %v, want active", approved["status"])
	}
	if approved["approved_by"] != bgAdminBUser {
		t.Fatalf("approved_by = %v, want %s", approved["approved_by"], bgAdminBUser)
	}

	// The grant shows up in the pending+active list.
	status, list := rcovDo(t, http.MethodGet, baseURL+"/api/v1/admin/break-glass", tokenA, nil)
	if status != http.StatusOK {
		t.Fatalf("list status = %d body=%v", status, list)
	}
	if total, _ := list["total"].(float64); total < 1 {
		t.Fatalf("list total = %v, want >= 1", list["total"])
	}

	// Revoke cascades and returns 200.
	status, revoked := rcovDo(t, http.MethodDelete, baseURL+"/api/v1/admin/break-glass/"+id, tokenA, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke status = %d body=%v", status, revoked)
	}
}

// TestBreakGlassRoutes_ReadonlyCreateHasNoSessionIDs proves a readonly-scope
// grant activates with zero minted sessions over the real HTTP path too.
func TestBreakGlassRoutes_ReadonlyCreateHasNoSessionIDs(t *testing.T) {
	baseURL, tokenA, _ := bgRoutesNewServer(t)
	status, created := rcovPostJSON(t, baseURL+"/api/v1/admin/break-glass", tokenA, map[string]any{
		"target_user_id": "user-2",
		"reason":         "ticket-1",
		"scope":          "readonly",
	})
	if status != http.StatusCreated {
		t.Fatalf("create status = %d body=%v", status, created)
	}
	if created["status"] != "active" {
		t.Fatalf("status = %v, want active (no approval required)", created["status"])
	}
	sids, _ := created["session_ids"].([]any)
	if len(sids) != 0 {
		t.Fatalf("readonly grant must mint zero sessions, got %v", sids)
	}
}

const bgImpTarget = "bg-target-user"

// bgImpNewServer mirrors bgRoutesNewServer but also seeds a TARGET user with a
// limited, non-admin role — so the impersonation NON-BYPASS invariant can be
// proven against the REAL permissions provider (the token must resolve to the
// target's boundary, never the admin's admin:*). Returns the server handle so
// tests can validate the minted bearer directly.
func bgImpNewServer(t *testing.T) (srv *sso.Server, baseURL, tokenA, tokenB string) {
	t.Helper()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: bgAdminAUser})
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: bgAdminBUser})
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: bgImpTarget})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: bgRoutesClient, Secret: bgRoutesSecret, Name: "Break-Glass Test Client",
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
	})

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, bgAdminAUser, "", []string{"root"})
	_ = prov.AssignRoles(ctx, bgAdminBUser, "", []string{"root"})
	_ = prov.AddRole(ctx, bgRoutesClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, bgAdminAUser, bgRoutesClient, []string{"root"})
	_ = prov.AssignRoles(ctx, bgAdminBUser, bgRoutesClient, []string{"root"})
	// The TARGET's own boundary — the impersonation token must resolve to THIS,
	// and never to admin:*.
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "member", Permissions: []string{"profile:read"}})
	_ = prov.AssignRoles(ctx, bgImpTarget, "", []string{"member"})

	srv = sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(bgRoutesPasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithBreakGlassStore(memorystoreidentity.NewMemoryBreakGlassStore()),
	)
	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)
	tokenA = bgRoutesLogin(t, httpSrv.URL, "admin-a", "pw-a")
	tokenB = bgRoutesLogin(t, httpSrv.URL, "admin-b", "pw-b")
	return srv, httpSrv.URL, tokenA, tokenB
}

func bgHasPerm(perms []permissions.Permission, code string) bool {
	for _, p := range perms {
		if p.Code == code {
			return true
		}
	}
	return false
}

// TestBreakGlassRoutes_ImpersonateMintsTargetBoundedRevocableBearer is the
// security-critical end-to-end proof: an active+approved impersonate grant mints
// a bearer that (1) authenticates as the TARGET (sub=target, act=admin), (2)
// carries no admin scope and resolves to the target's OWN permission boundary
// via the real provider (NON-BYPASS), (3) expires no later than the grant, and
// (4) is invalidated the instant the grant is revoked.
func TestBreakGlassRoutes_ImpersonateMintsTargetBoundedRevocableBearer(t *testing.T) {
	srv, baseURL, tokenA, _ := bgImpNewServer(t)
	ctx := context.Background()

	status, created := rcovPostJSON(t, baseURL+"/api/v1/admin/break-glass", tokenA, map[string]any{
		"target_user_id": bgImpTarget, "reason": "ticket-7", "scope": "impersonate",
	})
	if status != http.StatusCreated {
		t.Fatalf("create status=%d body=%v", status, created)
	}
	id, _ := created["id"].(string)

	status, imp := rcovDo(t, http.MethodPost, baseURL+"/api/v1/admin/break-glass/"+id+"/impersonate", tokenA, nil)
	if status != http.StatusOK {
		t.Fatalf("impersonate status=%d body=%v", status, imp)
	}
	token, _ := imp["access_token"].(string)
	if token == "" {
		t.Fatalf("no access_token in impersonate response: %v", imp)
	}

	claims, err := srv.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("impersonation token must validate: %v", err)
	}
	if claims.Subject != bgImpTarget {
		t.Fatalf("sub=%q, want target %q (NEVER the admin)", claims.Subject, bgImpTarget)
	}
	if claims.Actor == nil || claims.Actor.Subject != bgAdminAUser {
		t.Fatalf("act claim=%+v, want admin %q", claims.Actor, bgAdminAUser)
	}
	if len(claims.Scopes) != 0 {
		t.Fatalf("impersonation token must carry NO scope, got %v", claims.Scopes)
	}
	perms, _ := srv.Permissions().Permissions(ctx, claims.Subject, "")
	if !bgHasPerm(perms, "profile:read") || bgHasPerm(perms, "admin:*") {
		t.Fatalf("impersonated perms=%v, want target's profile:read and NO admin:*", perms)
	}

	// NON-ESCALATION: the impersonation bearer CANNOT reach the admin plane —
	// admin authorization keys off the token subject (the target user), who
	// holds no admin scope. This is the SAME check every user token flows
	// through; the bearer is treated exactly as the target's own token.
	if st, _ := rcovDo(t, http.MethodGet, baseURL+"/api/v1/admin/break-glass", token, nil); st != http.StatusForbidden {
		t.Fatalf("impersonation token on an admin endpoint = %d, want 403 (no privilege escalation)", st)
	}

	// TTL-bound: the token's exp is no later than the grant window.
	grantExp, _ := time.Parse(time.RFC3339, asString(created["expires_at"]))
	if !grantExp.IsZero() && claims.ExpiresAt.After(grantExp.Add(2*time.Second)) {
		t.Fatalf("token exp %v outlives grant window %v", claims.ExpiresAt, grantExp)
	}

	// Revoking the grant invalidates the credential immediately (cascade).
	if rst, _ := rcovDo(t, http.MethodDelete, baseURL+"/api/v1/admin/break-glass/"+id, tokenA, nil); rst != http.StatusOK {
		t.Fatalf("revoke status=%d", rst)
	}
	if _, err := srv.ValidateToken(ctx, token); err == nil {
		t.Fatalf("revoking the grant MUST invalidate the impersonation bearer")
	}
}

func asString(v any) string { s, _ := v.(string); return s }

// TestBreakGlassRoutes_ImpersonateGates proves readonly (structural), pending,
// and non-owner grants can NOT mint an impersonation bearer over the real path.
func TestBreakGlassRoutes_ImpersonateGates(t *testing.T) {
	_, baseURL, tokenA, tokenB := bgImpNewServer(t)

	_, ro := rcovPostJSON(t, baseURL+"/api/v1/admin/break-glass", tokenA, map[string]any{
		"target_user_id": bgImpTarget, "reason": "t", "scope": "readonly"})
	st, body := rcovDo(t, http.MethodPost, baseURL+"/api/v1/admin/break-glass/"+asString(ro["id"])+"/impersonate", tokenA, nil)
	if st != http.StatusForbidden || body["error"] != "break_glass_not_impersonable" {
		t.Fatalf("readonly impersonate = %d %v, want 403 break_glass_not_impersonable", st, body)
	}

	_, pend := rcovPostJSON(t, baseURL+"/api/v1/admin/break-glass", tokenA, map[string]any{
		"target_user_id": bgImpTarget, "reason": "t", "scope": "impersonate", "require_approval": true})
	st, body = rcovDo(t, http.MethodPost, baseURL+"/api/v1/admin/break-glass/"+asString(pend["id"])+"/impersonate", tokenA, nil)
	if st != http.StatusConflict || body["error"] != "break_glass_not_active" {
		t.Fatalf("pending impersonate = %d %v, want 409 break_glass_not_active", st, body)
	}

	_, act := rcovPostJSON(t, baseURL+"/api/v1/admin/break-glass", tokenA, map[string]any{
		"target_user_id": bgImpTarget, "reason": "t", "scope": "impersonate"})
	st, body = rcovDo(t, http.MethodPost, baseURL+"/api/v1/admin/break-glass/"+asString(act["id"])+"/impersonate", tokenB, nil)
	if st != http.StatusForbidden || body["error"] != "break_glass_not_owner" {
		t.Fatalf("non-owner impersonate = %d %v, want 403 break_glass_not_owner", st, body)
	}
}
