package sso_test

// rootcov_me_test.go drives the authenticated /me/* self-service portal so the
// me_handler.go / me_sessions.go / me_mfa.go / me_security.go handlers and the
// shared meSubjectOrChallenge / meClaimsOrChallenge bearer gate are covered.
// Reuses the rcov* helpers from rootcov_flow_test.go.

import (
	"context"
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

// rcovTenantUserStore returns a fresh in-memory B2B membership store.
func rcovTenantUserStore() *defaultimpl.MemoryTenantUserStore {
	return defaultimpl.NewMemoryTenantUserStore()
}

// TestRcovMe_Overview covers GET /me (profile + counts) and its 401 gate.
func TestRcovMe_Overview(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/me", access, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /me status=%d body=%v", status, out)
	}
	if out["sub"] != rcovUser {
		t.Errorf("sub = %v, want %q", out["sub"], rcovUser)
	}
	if out["user"] == nil {
		t.Errorf("expected user object in /me: %v", out)
	}

	// No bearer => 401.
	status, _ = rcovDo(t, http.MethodGet, s.http.URL+"/me", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("unauth /me = %d, want 401", status)
	}
}

// TestRcovMe_PatchProfile covers PATCH /me including the self-editable-attr
// allowlist (nickname allowed, role dropped).
func TestRcovMe_PatchProfile(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovDo(t, http.MethodPatch, s.http.URL+"/me", access, map[string]any{
		"name": "Alice Renamed",
		"attributes": map[string]string{
			"nickname": "ally",      // in allowlist
			"role":     "superuser", // NOT in allowlist => silently dropped
		},
	})
	if status != http.StatusOK {
		t.Fatalf("PATCH /me status=%d body=%v", status, out)
	}
	u, _ := out["user"].(map[string]any)
	if u == nil {
		t.Fatalf("no user in PATCH response: %v", out)
	}
	if u["name"] != "Alice Renamed" {
		t.Errorf("name not updated: %v", u["name"])
	}

	// Confirm the allowlist was enforced server-side.
	got, err := s.users.GetByID(context.Background(), rcovUser)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Attributes["nickname"] != "ally" {
		t.Errorf("nickname attr not persisted: %v", got.Attributes)
	}
	if got.Attributes["role"] == "superuser" {
		t.Errorf("role attr escalated past allowlist: %v", got.Attributes)
	}
}

// TestRcovMe_ChangePassword covers POST /me/password success + wrong-current.
func TestRcovMe_ChangePassword(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	// Wrong current password => 400 invalid_password.
	status, out := rcovPostJSON(t, s.http.URL+"/me/password", access, map[string]any{
		"current_password": "definitely-wrong",
		"new_password":     "brand-new-pw",
	})
	if status != http.StatusBadRequest {
		t.Errorf("wrong-current change = %d, want 400 (body=%v)", status, out)
	}

	// Correct current password => 204.
	status, _ = rcovPostJSON(t, s.http.URL+"/me/password", access, map[string]any{
		"current_password": rcovPassword,
		"new_password":     "brand-new-pw",
	})
	if status != http.StatusNoContent {
		t.Errorf("change password = %d, want 204", status)
	}
	if err := s.passwd.VerifyPassword(context.Background(), rcovUser, "brand-new-pw"); err != nil {
		t.Errorf("new password not set: %v", err)
	}

	// Missing fields => 400.
	status, _ = rcovPostJSON(t, s.http.URL+"/me/password", access, map[string]any{
		"new_password": "x",
	})
	if status != http.StatusBadRequest {
		t.Errorf("missing-current change = %d, want 400", status)
	}
}

// TestRcovMe_Sessions covers GET /sessions/me, DELETE /sessions/me/:id, and
// DELETE /sessions/me (sign out everywhere).
func TestRcovMe_Sessions(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/sessions/me", access, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /sessions/me status=%d body=%v", status, out)
	}
	sessions, _ := out["sessions"].([]any)
	if len(sessions) == 0 {
		t.Fatalf("expected at least one active session: %v", out)
	}

	// Delete a non-existent session of mine => 404 (oracle-safe).
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/sessions/me/does-not-exist", access, nil)
	if status != http.StatusNotFound {
		t.Errorf("delete missing session = %d, want 404", status)
	}

	// Sign out everywhere => 200 {revoked: N}.
	status, out = rcovDo(t, http.MethodDelete, s.http.URL+"/sessions/me", access, nil)
	if status != http.StatusOK {
		t.Errorf("sign-out-everywhere = %d, want 200 (body=%v)", status, out)
	}
}

// TestRcovMe_DeleteOwnSession revokes a concrete session the user owns.
func TestRcovMe_DeleteOwnSession(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	// Create a known session id via the store, then delete it through the handler.
	sess, err := s.sessions.Create(context.Background(), rcovUser)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	status, _ := rcovDo(t, http.MethodDelete, s.http.URL+"/sessions/me/"+sess.ID, access, nil)
	if status != http.StatusNoContent {
		t.Errorf("delete own session = %d, want 204", status)
	}
}

// TestRcovMe_Consents covers GET /consents/me + DELETE /consents/me/:client_id.
func TestRcovMe_Consents(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	// Seed a consent grant directly so the list has content.
	if err := s.consents.RecordConsent(context.Background(), core.ConsentGrant{
		UserID: rcovUser, ClientID: "some-app", Scopes: []string{"openid"},
	}); err != nil {
		t.Fatalf("record consent: %v", err)
	}

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/consents/me", access, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /consents/me status=%d body=%v", status, out)
	}
	grants, _ := out["consents"].([]any)
	if len(grants) != 1 {
		t.Errorf("consents = %d, want 1 (body=%v)", len(grants), out)
	}

	// Revoke it => 204.
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/consents/me/some-app", access, nil)
	if status != http.StatusNoContent {
		t.Errorf("revoke consent = %d, want 204", status)
	}

	// Revoking a missing grant => 404.
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/consents/me/unknown-app", access, nil)
	if status != http.StatusNotFound {
		t.Errorf("revoke missing consent = %d, want 404", status)
	}
}

// TestRcovMe_MFAFactors covers GET /me/mfa + DELETE /me/mfa/:id.
func TestRcovMe_MFAFactors(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/me/mfa", access, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /me/mfa status=%d body=%v", status, out)
	}
	if _, ok := out["factors"]; !ok {
		t.Errorf("expected factors key: %v", out)
	}

	// Delete a factor the user does not have => 404 (oracle-safe).
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/me/mfa/no-such-factor", access, nil)
	if status != http.StatusNotFound {
		t.Errorf("delete unknown factor = %d, want 404", status)
	}
}

// TestRcovMe_Permissions covers the permission/menu/role self endpoints, which
// degrade gracefully when no permission provider is wired.
func TestRcovMe_Permissions(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	// With no permission provider wired these return 501 Not Implemented — a
	// deliberate, byte-identical "feature off" response, not a 500 fault.
	for _, path := range []string{"/permissions/me", "/menus/me", "/roles/me"} {
		status, _ := rcovDo(t, http.MethodGet, s.http.URL+path, access, nil)
		if status != http.StatusNotImplemented && status != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 or 501", path, status)
		}
	}
}

// TestRcovMe_Organizations covers GET /me/organizations when a tenant-user store
// is wired (and DELETE leave).
func TestRcovMe_Organizations(t *testing.T) {
	t.Parallel()
	tu := rcovTenantUserStore()
	s := rcovNewServer(t, sso.WithTenantUserStore(tu))
	access, _ := rcovDirectLogin(t, s)

	// Seed a membership for the user.
	if err := tu.Add(context.Background(), &core.TenantMembership{
		TenantID: "org-1", UserID: rcovUser, Role: core.TenantRoleMember,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/me/organizations", access, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /me/organizations status=%d body=%v", status, out)
	}
	orgs, _ := out["organizations"].([]any)
	if len(orgs) != 1 {
		t.Errorf("organizations = %d, want 1 (body=%v)", len(orgs), out)
	}

	// Leave the org => 204, idempotent.
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/me/organizations/org-1", access, nil)
	if status != http.StatusNoContent {
		t.Errorf("leave org = %d, want 204", status)
	}
}
