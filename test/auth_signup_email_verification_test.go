package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// captureSender records the last token sent via SendEmailVerificationToken
// so the test can inspect or consume it. Thread-safe for single-goroutine tests.
type captureSender struct {
	lastEmail string
	lastToken string
}

func (c *captureSender) SendEmailVerificationToken(_ context.Context, email, token string) error {
	c.lastEmail = email
	c.lastToken = token
	return nil
}

// newSignupVerificationHarness creates a test server with signup and email
// verification enabled. When requireVerification is true, mandatory Mode B is
// used; when false, optional Mode A is used.
func newSignupVerificationHarness(t *testing.T, requireVerification bool) (
	*httptest.Server,
	*defaultimpl.MemoryUserProvider,
	*defaultimpl.MemoryPasswordCredentialStore,
	*defaultimpl.MemoryEmailVerificationStore,
	*captureSender,
) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	pw := defaultimpl.NewMemoryPasswordCredentialStore()
	evStore := defaultimpl.NewMemoryEmailVerificationStore()
	sender := &captureSender{}
	opts := []sso.Option{
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithUserProvider(users),
		sso.WithPasswordCredentialStore(pw),
		sso.WithSelfServiceSignup(),
		sso.WithEmailVerificationStore(evStore, 0), // 0 = SDK default TTL
		sso.WithEmailVerificationSender(sender),
	}
	if requireVerification {
		opts = append(opts, sso.WithSignupRequireVerification(true))
	}
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)
	return hs, users, pw, evStore, sender
}

// postRegister sends a POST /auth/register request and returns the response.
func postRegister(t *testing.T, srv *httptest.Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/register", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /auth/register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// postVerifyEmail sends a POST /auth/verify-email request and returns the response.
func postVerifyEmail(t *testing.T, srv *httptest.Server, token string) (int, map[string]any) {
	t.Helper()
	body := map[string]any{"token": token}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/verify-email", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /auth/verify-email: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestSignup_ModeA_NoEmail_NoVerification verifies that a signup without
// email succeeds with status "created" and no email_verified attribute.
func TestSignup_ModeA_NoEmail_NoVerification(t *testing.T) {
	srv, users, pw, _, _ := newSignupVerificationHarness(t, false)
	ctx := context.Background()

	code, body := postRegister(t, srv, map[string]any{
		"username": "noemail", "password": "pw12345678",
	})
	if code != http.StatusCreated || body["status"] != "created" {
		t.Fatalf("signup = %d %v, want 201 created", code, body)
	}
	u, err := users.GetByID(ctx, "noemail")
	if err != nil || u == nil {
		t.Fatalf("user not created: %v", err)
	}
	if u.Attributes != nil && u.Attributes["email_verified"] != "" {
		t.Errorf("unexpected email_verified attribute without email: %v", u.Attributes)
	}
	if err := pw.VerifyPassword(ctx, "noemail", "pw12345678"); err != nil {
		t.Errorf("password not set: %v", err)
	}
}

// TestSignup_ModeA_WithEmail_EmailVerified verifies that Mode A with email
// sets email_verified="true" immediately.
func TestSignup_ModeA_WithEmail_EmailVerified(t *testing.T) {
	srv, users, _, _, _ := newSignupVerificationHarness(t, false)
	ctx := context.Background()

	code, body := postRegister(t, srv, map[string]any{
		"username": "hasemail", "password": "pw12345678", "email": "user@example.com",
	})
	if code != http.StatusCreated || body["status"] != "created" {
		t.Fatalf("signup = %d %v, want 201 created", code, body)
	}
	u, err := users.GetByID(ctx, "hasemail")
	if err != nil || u == nil {
		t.Fatalf("user not created: %v", err)
	}
	if u.Email != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", u.Email)
	}
	if u.Attributes == nil || u.Attributes["email_verified"] != "true" {
		t.Errorf("email_verified not set to true: %v", u.Attributes)
	}
}

// TestSignup_ModeB_RequireEmail verifies that Mode B requires email and
// returns 400 when omitted.
func TestSignup_ModeB_RequireEmail(t *testing.T) {
	srv, _, _, _, _ := newSignupVerificationHarness(t, true)

	code, body := postRegister(t, srv, map[string]any{
		"username": "needemail", "password": "pw12345678",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("mode B no email = %d %v, want 400", code, body)
	}
}

// TestSignup_ModeB_PendingStatus verifies that Mode B returns 201 pending
// without creating a user account.
func TestSignup_ModeB_PendingStatus(t *testing.T) {
	srv, users, _, _, _ := newSignupVerificationHarness(t, true)
	ctx := context.Background()

	code, body := postRegister(t, srv, map[string]any{
		"username": "pendinguser", "password": "pw12345678", "email": "pending@example.com",
	})
	if code != http.StatusCreated || body["status"] != "pending" {
		t.Fatalf("mode B signup = %d %v, want 201 pending", code, body)
	}
	// User should NOT exist yet — the account is only created after
	// email verification.
	if u, _ := users.GetByID(ctx, "pendinguser"); u != nil {
		t.Errorf("user created before email verification: %v", u)
	}
}

// TestSignup_ModeB_VerifyEmail verifies the full Mode B flow: register →
// verify email → user created with email_verified=true.
func TestSignup_ModeB_VerifyEmail(t *testing.T) {
	srv, users, pw, _, sender := newSignupVerificationHarness(t, true)
	ctx := context.Background()

	// Register — captures the token in sender.lastToken.
	code, body := postRegister(t, srv, map[string]any{
		"username": "verifyuser", "password": "pw12345678", "email": "verify@example.com",
	})
	if code != http.StatusCreated || body["status"] != "pending" {
		t.Fatalf("mode B signup = %d %v, want 201 pending", code, body)
	}
	if sender.lastToken == "" {
		t.Fatal("no token captured by sender")
	}
	if sender.lastEmail != "verify@example.com" {
		t.Errorf("sender.email = %q, want verify@example.com", sender.lastEmail)
	}

	// Consume the token via /auth/verify-email.
	code, body = postVerifyEmail(t, srv, sender.lastToken)
	if code != http.StatusOK || body["status"] != "verified" {
		t.Fatalf("verify-email = %d %v, want 200 verified", code, body)
	}

	// User should now exist with email_verified=true.
	u, err := users.GetByID(ctx, "verifyuser")
	if err != nil || u == nil {
		t.Fatalf("user not created after verify: %v", err)
	}
	if u.Email != "verify@example.com" {
		t.Errorf("email = %q, want verify@example.com", u.Email)
	}
	if u.Attributes == nil || u.Attributes["email_verified"] != "true" {
		t.Errorf("email_verified not set to true: %v", u.Attributes)
	}
	// Password should be set (via PasswordHashImporter).
	if err := pw.VerifyPassword(ctx, "verifyuser", "pw12345678"); err != nil {
		t.Errorf("password not set after verify: %v", err)
	}
}

// TestVerifyEmail_InvalidToken verifies that an unknown/expired/consumed
// token returns 400 verification_invalid (oracle-safe).
func TestVerifyEmail_InvalidToken(t *testing.T) {
	srv, _, _, _, _ := newSignupVerificationHarness(t, true)

	code, body := postVerifyEmail(t, srv, "not-a-real-token")
	if code != http.StatusBadRequest {
		t.Fatalf("verify invalid token = %d %v, want 400", code, body)
	}
	if body["error"] != "verification_invalid" {
		t.Errorf("error = %q, want verification_invalid", body["error"])
	}
}

// TestVerifyEmail_EmptyToken verifies that an empty token returns 400
// verification_invalid.
func TestVerifyEmail_EmptyToken(t *testing.T) {
	srv, _, _, _, _ := newSignupVerificationHarness(t, true)

	code, body := postVerifyEmail(t, srv, "")
	if code != http.StatusBadRequest {
		t.Fatalf("verify empty token = %d %v, want 400", code, body)
	}
}

// TestVerifyEmail_DoubleConsume verifies that a token can only be consumed
// once (oracle-safe: second attempt returns 400 verification_invalid).
func TestVerifyEmail_DoubleConsume(t *testing.T) {
	srv, _, _, _, sender := newSignupVerificationHarness(t, true)

	code, body := postRegister(t, srv, map[string]any{
		"username": "doubleconsume", "password": "pw12345678", "email": "double@example.com",
	})
	if code != http.StatusCreated {
		t.Fatalf("signup = %d %v, want 201", code, body)
	}
	if sender.lastToken == "" {
		t.Fatal("no token captured")
	}

	// First consume — should succeed.
	code, body = postVerifyEmail(t, srv, sender.lastToken)
	if code != http.StatusOK {
		t.Fatalf("first verify = %d %v, want 200", code, body)
	}

	// Second consume with the same token — should fail.
	code, body = postVerifyEmail(t, srv, sender.lastToken)
	if code != http.StatusBadRequest || body["error"] != "verification_invalid" {
		t.Fatalf("double consume = %d %v, want 400 verification_invalid", code, body)
	}
}
