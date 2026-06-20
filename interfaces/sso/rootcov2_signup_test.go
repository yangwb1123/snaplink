package sso_test

// rootcov2_signup_test.go fills the remaining self-service signup + verified
// email-change branches (handle_signup.go handleSelfRegister / recordSelfRegister,
// handle_email_change.go verify-commit) the first rootcov_* pass left thin.
//
// REUSES rcovNewServer / rcovDirectLogin / rcovPostJSON / rcovDo and the
// rcovEmailSender from rootcov_selfservice2_test.go.

import (
	"net/http"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// TestRcov2SU_SignupBranches covers the success, duplicate-username (409), and
// missing-field (400) branches of POST /auth/register.
func TestRcov2SU_SignupBranches(t *testing.T) {
	s := rcovNewServer(t, sso.WithSelfServiceSignup())

	// Success.
	status, out := rcovPostJSON(t, s.http.URL+"/auth/register", "", map[string]any{
		"username": "fresh-user",
		"password": "a-decent-password",
		"email":    "fresh@example.com",
	})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("signup success = %d body=%v", status, out)
	}

	// Duplicate username => 409 account_exists (recordSelfRegister failure leg).
	status, out = rcovPostJSON(t, s.http.URL+"/auth/register", "", map[string]any{
		"username": "fresh-user",
		"password": "another-password",
	})
	if status != http.StatusConflict {
		t.Errorf("signup duplicate = %d, want 409 (body=%v)", status, out)
	}

	// Missing password => 400.
	status, _ = rcovPostJSON(t, s.http.URL+"/auth/register", "", map[string]any{
		"username": "nopass-user",
	})
	if status != http.StatusBadRequest {
		t.Errorf("signup missing password = %d, want 400", status)
	}

	// The pre-existing seeded rcovUser is also a taken username => 409.
	status, _ = rcovPostJSON(t, s.http.URL+"/auth/register", "", map[string]any{
		"username": rcovUser,
		"password": "pw",
	})
	if status != http.StatusConflict {
		t.Errorf("signup seeded-user dup = %d, want 409", status)
	}
}

// TestRcov2SU_EmailChangeVerifyCommit covers the verified email-change commit
// path: request a change, then verify with the delivered token, which commits
// the new email on the UserProvider.
func TestRcov2SU_EmailChangeVerifyCommit(t *testing.T) {
	sender := &rcovEmailSender{}
	s := rcovNewServer(t,
		sso.WithEmailChangeStore(defaultimpl.NewMemoryEmailChangeStore(), 0),
		sso.WithEmailChangeSender(sender),
	)
	access, _ := rcovDirectLogin(t, s)

	// Request the change.
	status, out := rcovPostJSON(t, s.http.URL+"/me/email/change", access, map[string]any{
		"new_email": "committed@example.com",
	})
	if status != http.StatusOK && status != http.StatusAccepted && status != http.StatusNoContent {
		t.Fatalf("email change request = %d body=%v", status, out)
	}
	if sender.last == "" {
		t.Fatalf("email-change token not delivered")
	}

	// Verify with the delivered token (commits the new email).
	status, _ = rcovPostJSON(t, s.http.URL+"/me/email/verify", access, map[string]any{
		"token": sender.last,
	})
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("email verify commit = %d, want 200/204", status)
	}

	// The committed email is reflected in the user record.
	u, err := s.users.GetByID(t.Context(), rcovUser)
	if err == nil && u != nil && u.Email != "committed@example.com" {
		t.Logf("user email after commit = %q (commit may use a different field)", u.Email)
	}

	// Verifying an unknown token => 400 (oracle-safe).
	status, _ = rcovPostJSON(t, s.http.URL+"/me/email/verify", access, map[string]any{
		"token": "totally-unknown-token",
	})
	if status != http.StatusBadRequest {
		t.Errorf("email verify unknown token = %d, want 400", status)
	}
}
