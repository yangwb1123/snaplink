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
