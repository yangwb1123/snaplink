package sso_test

// rootcov_admin_password_reset_test.go covers
// POST /api/v1/admin/users/{id}/password — proving the admin-initiated
// password reset now respects a wired PasswordHistoryStore exactly like the
// self-service reset does, closing the gap where the highest-privilege
// credential-change path was a back door around history enforcement.

import (
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystorecredential"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// TestRcovAdmin_ResetUserPasswordRejectsHistoryReuse proves the admin
// password-reset endpoint rejects reinstating a password already in the
// user's history, then accepts and records a genuinely fresh one.
func TestRcovAdmin_ResetUserPasswordRejectsHistoryReuse(t *testing.T) {
	t.Parallel()
	passwords := defaultimpl.NewMemoryPasswordCredentialStore()
	history := memorystorecredential.NewMemoryPasswordHistoryStore(3)
	env := rcovNewAdminServer(t,
		sso.WithPasswordCredentialStore(passwords),
		sso.WithPasswordHistoryStore(history),
	)
	_ = passwords.SetPassword(t.Context(), rcovUser, "original-password")
	_ = history.Record(t.Context(), rcovUser, "original-password")

	status, out := rcovDo(t, http.MethodPost, env.url+"/api/v1/admin/users/"+rcovUser+"/password", env.token,
		map[string]any{"new_password": "original-password"})
	if status != http.StatusBadRequest {
		t.Fatalf("reusing the current password: status = %d, want 400, body=%v", status, out)
	}
	if out["error"] != "password_policy_violation" {
		t.Fatalf("error = %v, want password_policy_violation", out["error"])
	}
	if err := passwords.VerifyPassword(t.Context(), rcovUser, "original-password"); err != nil {
		t.Error("password must be unchanged after a rejected reuse")
	}

	status, out = rcovDo(t, http.MethodPost, env.url+"/api/v1/admin/users/"+rcovUser+"/password", env.token,
		map[string]any{"new_password": "brand-new-password"})
	if status != http.StatusNoContent {
		t.Fatalf("fresh password: status = %d, want 204, body=%v", status, out)
	}
	reused, err := history.CheckHistory(t.Context(), rcovUser, "brand-new-password")
	if err != nil || !reused {
		t.Errorf("the just-set password should now be in history, got (%v, %v)", reused, err)
	}
}

// TestRcovAdmin_ResetUserPasswordNoHistoryStoreSucceeds proves the endpoint
// is unaffected when no history store is wired (the default) — byte-
// identical to a build without the feature.
func TestRcovAdmin_ResetUserPasswordNoHistoryStoreSucceeds(t *testing.T) {
	t.Parallel()
	env := rcovNewAdminServer(t)

	status, out := rcovDo(t, http.MethodPost, env.url+"/api/v1/admin/users/"+rcovUser+"/password", env.token,
		map[string]any{"new_password": "any-password-at-all"})
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body=%v", status, out)
	}
}
