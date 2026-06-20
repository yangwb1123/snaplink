package sso_test

// rootcov_admin_test.go drives the admin / B2B management handlers
// (handlers_admin.go + handlers_b2b.go) through the real AdminMiddleware so the
// admin:read / admin:write gate, the actor-from-context plumbing, and each
// handler body are covered. The login user is granted admin:* under its token
// audience (= client_id), then a bearer-authenticated admin client hits the
// /api/v1/admin/* surface.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/security"
)

// rcovAdminEnv bundles an admin-gated httptest server with the login token and
// the stores admin handlers mutate.
type rcovAdminEnv struct {
	url     string
	token   string
	conns   *connections.MemoryStore
	tenants *defaultimpl.MemoryTenantUserStore
}

// rcovNewAdminServer builds a server wired with the B2B + self-service stores,
// fronts it with AdminMiddleware authorizing rcovUser as admin:*, and returns a
// logged-in token. The middleware authorizes on (subject, audience) where the
// audience is the token's client_id.
func rcovNewAdminServer(t *testing.T) *rcovAdminEnv {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, Name: "Admin Client",
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
	})
	pw := rcovPasswordAuthAccepting()

	conns := connections.NewMemoryStore()
	tenants := defaultimpl.NewMemoryTenantUserStore()

	prov := permissions.NewMemoryProvider()
	// admin:* under the empty-string client scope; the token audience is the
	// client_id, so grant under that too to be robust to either resolution.
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, "", []string{"root"})
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"root"})

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithConnectionStore(conns),
		sso.WithTenantUserStore(tenants),
		sso.WithInvitationStore(defaultimpl.NewMemoryInvitationStore()),
		sso.WithConsentStore(defaultimpl.NewMemoryConsentStore()),
		sso.WithMFAEnrollmentStore(defaultimpl.NewMemoryMFAEnrollmentStore()),
		sso.WithPasswordCredentialStore(defaultimpl.NewMemoryPasswordCredentialStore()),
		sso.WithPasswordResetStore(defaultimpl.NewMemoryPasswordResetStore(), time.Hour),
		sso.WithEmailChangeStore(defaultimpl.NewMemoryEmailChangeStore(), time.Hour),
		sso.WithDeviceSecretStore(defaultimpl.NewMemoryDeviceSecretStore(), time.Hour),
		sso.WithAccountLockout(security.NewMemoryAccountLockout()),
		sso.WithPermissionProvider(prov),
	)

	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	// Login to obtain a real bearer token for rcovUser via rcovClient.
	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("admin login status=%d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no admin token: %v", out)
	}
	return &rcovAdminEnv{url: httpSrv.URL, token: token, conns: conns, tenants: tenants}
}

// rcovPasswordAuthAccepting returns a password authenticator accepting the
// canonical rcov credentials. Defined here so the admin server doesn't depend on
// the rcovNewServer helper (which wires consent etc.).
func rcovPasswordAuthAccepting() sso.Authenticator {
	return authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{UserID: rcovUser, AuthMethods: []string{"pwd"}}, nil
			}
			return nil, errors.New("bad credentials")
		},
	))
}

// TestRcovAdmin_Gate confirms the middleware rejects unauthenticated + non-admin.
func TestRcovAdmin_Gate(t *testing.T) {
	env := rcovNewAdminServer(t)

	// No bearer => 401.
	status, _ := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/connections?tenant_id=org-1", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("no-bearer admin = %d, want 401", status)
	}
	// Garbage bearer => 401.
	status, _ = rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/connections?tenant_id=org-1", "garbage", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("bad-bearer admin = %d, want 401", status)
	}
}

// TestRcovAdmin_Connections covers the enterprise-connection CRUD handlers.
func TestRcovAdmin_Connections(t *testing.T) {
	env := rcovNewAdminServer(t)

	// Upsert a connection.
	status, out := rcovPostJSON(t, env.url+"/api/v1/admin/connections", env.token, map[string]any{
		"id": "conn-1", "tenant_id": "org-1", "type": "oidc",
		"display_name": "Acme OIDC", "domains": []string{"acme.example"}, "enabled": true,
	})
	if status != http.StatusOK {
		t.Fatalf("upsert connection = %d body=%v", status, out)
	}

	// List the tenant's connections.
	status, out = rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/connections?tenant_id=org-1", env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("list connections = %d body=%v", status, out)
	}
	conns, _ := out["connections"].([]any)
	if len(conns) != 1 {
		t.Errorf("connections = %d, want 1 (body=%v)", len(conns), out)
	}

	// Get it by id.
	status, _ = rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/connections/conn-1", env.token, nil)
	if status != http.StatusOK {
		t.Errorf("get connection = %d, want 200", status)
	}

	// Get a missing connection => 404.
	status, _ = rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/connections/nope", env.token, nil)
	if status != http.StatusNotFound {
		t.Errorf("get missing connection = %d, want 404", status)
	}

	// Delete it => 204 (idempotent).
	status, _ = rcovDo(t, http.MethodDelete, env.url+"/api/v1/admin/connections/conn-1", env.token, nil)
	if status != http.StatusNoContent {
		t.Errorf("delete connection = %d, want 204", status)
	}

	// Upsert with a bad type => 400.
	status, _ = rcovPostJSON(t, env.url+"/api/v1/admin/connections", env.token, map[string]any{
		"id": "conn-2", "tenant_id": "org-1", "type": "ldap",
	})
	if status != http.StatusBadRequest {
		t.Errorf("upsert bad type = %d, want 400", status)
	}
}

// TestRcovAdmin_TenantMembers covers the org-roster admin handlers.
func TestRcovAdmin_TenantMembers(t *testing.T) {
	env := rcovNewAdminServer(t)

	// Add a member.
	status, _ := rcovDo(t, http.MethodPut, env.url+"/api/v1/admin/tenants/org-1/members/bob", env.token, map[string]any{
		"role": "admin",
	})
	if status != http.StatusOK {
		t.Fatalf("put tenant member = %d", status)
	}

	// List members.
	status, out := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/tenants/org-1/members", env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("list members = %d body=%v", status, out)
	}
	members, _ := out["members"].([]any)
	if len(members) != 1 {
		t.Errorf("members = %d, want 1 (body=%v)", len(members), out)
	}

	// Bad role => 400.
	status, _ = rcovDo(t, http.MethodPut, env.url+"/api/v1/admin/tenants/org-1/members/carol", env.token, map[string]any{
		"role": "emperor",
	})
	if status != http.StatusBadRequest {
		t.Errorf("put bad role = %d, want 400", status)
	}

	// Remove the member => 204.
	status, _ = rcovDo(t, http.MethodDelete, env.url+"/api/v1/admin/tenants/org-1/members/bob", env.token, nil)
	if status != http.StatusNoContent {
		t.Errorf("remove member = %d, want 204", status)
	}
}

// TestRcovAdmin_Invitations covers the invitation send/list handlers. Without an
// InvitationSender wired, send returns 501 (the token must never be returned).
func TestRcovAdmin_Invitations(t *testing.T) {
	env := rcovNewAdminServer(t)

	// Send without a sender => 501.
	status, _ := rcovPostJSON(t, env.url+"/api/v1/admin/tenants/org-1/invitations", env.token, map[string]any{
		"email": "newbie@example.com", "role": "member",
	})
	if status != http.StatusNotImplemented {
		t.Errorf("send invitation (no sender) = %d, want 501", status)
	}

	// List pending invitations => 200 (empty).
	status, out := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/tenants/org-1/invitations", env.token, nil)
	if status != http.StatusOK {
		t.Errorf("list invitations = %d body=%v", status, out)
	}
}

// TestRcovAdmin_UserManagement covers the helpdesk user-state handlers: consents,
// MFA factors, password reset, email set, account-lockout clear, and the
// recovery-token list/revoke surfaces.
func TestRcovAdmin_UserManagement(t *testing.T) {
	env := rcovNewAdminServer(t)
	base := env.url + "/api/v1/admin/users/" + rcovUser

	// Consents: list (empty) + revoke a missing one (404).
	status, out := rcovDo(t, http.MethodGet, base+"/consents", env.token, nil)
	if status != http.StatusOK {
		t.Errorf("admin list consents = %d body=%v", status, out)
	}
	status, _ = rcovDo(t, http.MethodDelete, base+"/consents/unknown-app", env.token, nil)
	if status != http.StatusNotFound {
		t.Errorf("admin revoke missing consent = %d, want 404", status)
	}

	// MFA factors: list (empty) + remove a missing one (404).
	status, out = rcovDo(t, http.MethodGet, base+"/mfa", env.token, nil)
	if status != http.StatusOK {
		t.Errorf("admin list mfa = %d body=%v", status, out)
	}
	status, _ = rcovDo(t, http.MethodDelete, base+"/mfa/no-factor", env.token, nil)
	if status != http.StatusNotFound {
		t.Errorf("admin remove missing mfa = %d, want 404", status)
	}

	// Set password (admin override) => 204; empty body => 400.
	status, _ = rcovPostJSON(t, base+"/password", env.token, map[string]any{"new_password": "admin-set-pw"})
	if status != http.StatusNoContent {
		t.Errorf("admin set password = %d, want 204", status)
	}
	status, _ = rcovPostJSON(t, base+"/password", env.token, map[string]any{})
	if status != http.StatusBadRequest {
		t.Errorf("admin set empty password = %d, want 400", status)
	}

	// Set email => 204; missing-user 404.
	status, _ = rcovPostJSON(t, base+"/email", env.token, map[string]any{"email": "new@example.com"})
	if status != http.StatusNoContent {
		t.Errorf("admin set email = %d, want 204", status)
	}
	status, _ = rcovPostJSON(t, env.url+"/api/v1/admin/users/ghost/email", env.token, map[string]any{"email": "x@y.z"})
	if status != http.StatusNotFound {
		t.Errorf("admin set email missing user = %d, want 404", status)
	}

	// Clear account lockout (idempotent) => 204/200.
	status, _ = rcovPostJSON(t, env.url+"/api/v1/admin/account-lockout/clear", env.token, map[string]any{
		"client_id": rcovClient, "identifier": rcovUsername,
	})
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Errorf("admin clear lockout = %d, want 204/200", status)
	}

	// Device secrets revoke (idempotent) => 200/204.
	status, _ = rcovDo(t, http.MethodDelete, base+"/device-secrets", env.token, nil)
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Errorf("admin revoke device secrets = %d, want 200/204", status)
	}

	// Recovery-token list + revoke surfaces (empty but mounted).
	status, _ = rcovDo(t, http.MethodGet, base+"/password-reset-tokens", env.token, nil)
	if status != http.StatusOK {
		t.Errorf("admin list password-reset-tokens = %d, want 200", status)
	}
	status, _ = rcovDo(t, http.MethodDelete, base+"/password-reset-tokens", env.token, nil)
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Errorf("admin revoke password-reset-tokens = %d", status)
	}
	status, _ = rcovDo(t, http.MethodGet, base+"/email-change-tokens", env.token, nil)
	if status != http.StatusOK {
		t.Errorf("admin list email-change-tokens = %d, want 200", status)
	}
	status, _ = rcovDo(t, http.MethodDelete, base+"/email-change-tokens", env.token, nil)
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Errorf("admin revoke email-change-tokens = %d", status)
	}
}
