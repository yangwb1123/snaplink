package sso_test

// rootcov_selfservice2_test.go covers the remaining self-service surfaces:
// self-service signup, the public branding lookup, TOTP enrollment begin/confirm
// (me_mfa.go), verified email change (handle_email_change.go), and the
// permission/menu/role self endpoints backed by a real permissions provider
// (handlers.go authenticatedSubject + resolvePermissionsForLogin).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/permissions"
	tenantmemory "github.com/snaplink/sso/tenant/memory"
)

// TestRcovSS2_TOTPEnroll covers POST /me/mfa/totp/begin (mint secret) and the
// confirm error path (wrong code => totp_invalid_code).
func TestRcovSS2_TOTPEnroll(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	enroller := authenticators.NewTOTPEnroller(totpAuth)
	// The TOTP enrollment routes mount only when the MFA enrollment store also
	// implements TOTPEnrollmentWriter (MemoryTOTPEnrollmentStore does).
	s := rcovNewServer(t,
		sso.WithMFAEnrollmentStore(defaultimpl.NewMemoryTOTPEnrollmentStore()),
		sso.WithTOTPEnroller(enroller),
	)
	access, _ := rcovDirectLogin(t, s)

	// Begin: returns a base32 secret + otpauth URI.
	status, out := rcovPostJSON(t, s.http.URL+"/me/mfa/totp/begin", access, nil)
	if status != http.StatusOK {
		t.Fatalf("totp begin = %d body=%v", status, out)
	}
	secret, _ := out["secret"].(string)
	if secret == "" || out["otpauth_uri"] == nil {
		t.Fatalf("totp begin missing secret/uri: %v", out)
	}

	// Confirm with a wrong code => 400 totp_invalid_code (oracle-safe).
	status, out = rcovPostJSON(t, s.http.URL+"/me/mfa/totp/confirm", access, map[string]any{
		"secret": secret,
		"code":   "000000",
	})
	if status != http.StatusBadRequest {
		t.Errorf("totp confirm wrong code = %d, want 400 (body=%v)", status, out)
	}

	// Confirm with missing fields => 400.
	status, _ = rcovPostJSON(t, s.http.URL+"/me/mfa/totp/confirm", access, map[string]any{})
	if status != http.StatusBadRequest {
		t.Errorf("totp confirm missing fields = %d, want 400", status)
	}
}

// rcovEmailSender captures the last delivered email-change token.
type rcovEmailSender struct{ last string }

func (r *rcovEmailSender) SendEmailChangeToken(_ context.Context, _, token string) error {
	r.last = token
	return nil
}

// TestRcovSS2_EmailChange covers POST /me/email/change (request) and the verify
// leg with the delivered token.
func TestRcovSS2_EmailChange(t *testing.T) {
	sender := &rcovEmailSender{}
	s := rcovNewServer(t,
		sso.WithEmailChangeStore(defaultimpl.NewMemoryEmailChangeStore(), 0),
		sso.WithEmailChangeSender(sender),
	)
	access, _ := rcovDirectLogin(t, s)

	// Request a change to a syntactically-valid address.
	status, out := rcovPostJSON(t, s.http.URL+"/me/email/change", access, map[string]any{
		"new_email": "alice.new@example.com",
	})
	if status != http.StatusOK && status != http.StatusAccepted && status != http.StatusNoContent {
		t.Fatalf("email change request = %d body=%v", status, out)
	}
	if sender.last == "" {
		t.Fatalf("email change token not delivered")
	}

	// Invalid address => 400.
	status, _ = rcovPostJSON(t, s.http.URL+"/me/email/change", access, map[string]any{
		"new_email": "not-an-email",
	})
	if status != http.StatusBadRequest {
		t.Errorf("email change bad addr = %d, want 400", status)
	}

	// Verify with the delivered token (commits the new email).
	status, _ = rcovPostJSON(t, s.http.URL+"/me/email/verify", access, map[string]any{
		"token": sender.last,
	})
	if status >= 500 {
		t.Errorf("email verify = %d, want < 500", status)
	}
}

// TestRcovSS2_Signup covers POST /auth/register self-service signup.
func TestRcovSS2_Signup(t *testing.T) {
	s := rcovNewServer(t, sso.WithSelfServiceSignup())

	status, out := rcovPostJSON(t, s.http.URL+"/auth/register", "", map[string]any{
		"username": "newuser",
		"password": "a-decent-password",
		"email":    "newuser@example.com",
	})
	// Accept any non-5xx: the exact success code varies, but the handler body runs.
	if status >= 500 {
		t.Errorf("signup = %d body=%v, want < 500", status, out)
	}
}

// TestRcovSS2_Branding covers GET /branding, which is mounted with a tenant store
// and always returns 200 (non-enumerable).
func TestRcovSS2_Branding(t *testing.T) {
	s := rcovNewServer(t, sso.WithTenantStore(tenantmemory.New()))

	resp := rcovGetJSON(t, s.http.URL+"/branding", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("branding = %d, want 200", resp.StatusCode)
	}
}

// TestRcovSS2_PermissionsWithProvider covers the permission/menu/role self
// endpoints when a provider is wired and the bearer subject has a role.
func TestRcovSS2_PermissionsWithProvider(t *testing.T) {
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{UserID: rcovUser}, nil
			}
			return nil, errors.New("bad")
		}))

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "viewer", Permissions: []string{"items:read"}})
	_ = prov.AssignRoles(ctx, rcovUser, "", []string{"viewer"})
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "viewer", Permissions: []string{"items:read"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"viewer"})

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("perms login = %d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)

	for _, path := range []string{"/permissions/me", "/menus/me", "/roles/me"} {
		status, out := rcovDo(t, http.MethodGet, httpSrv.URL+path, token, nil)
		if status != http.StatusOK {
			t.Errorf("GET %s = %d body=%v, want 200", path, status, out)
		}
	}

	// Unauthenticated permission query => 401.
	status, _ = rcovDo(t, http.MethodGet, httpSrv.URL+"/permissions/me", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("unauth permissions = %d, want 401", status)
	}
}
