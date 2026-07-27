package sso_test

// rootcov2_admin_invite_test.go covers the admin org-invitation send/list flow
// (handlers_b2b.go handleAdminSendInvitation / handleAdminListInvitations +
// recordAdminUserAction) which needs an InvitationSender wired — the existing
// admin harness leaves the sender nil (501). It also exercises the
// embed-permissions-in-login path (discovery_handler.go resolvePermissionsForLogin).
//
// REUSES rcovPostJSON / rcovDo and the rcov* constants. Builds its own
// admin-gated server with the sender wired.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// rcov2AdminInviteSender records the last invitation delivery.
type rcov2AdminInviteSender struct {
	email, tenant, role, token string
}

func (s *rcov2AdminInviteSender) SendInvitation(_ context.Context, email, tenantID, role, token string) error {
	s.email, s.tenant, s.role, s.token = email, tenantID, role, token
	return nil
}

// TestRcov2AI_SendInvitation drives the admin send + list invitation handlers.
func TestRcov2AI_SendInvitation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, "", []string{"root"})
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"root"})

	sender := &rcov2AdminInviteSender{}
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithInvitationStore(defaultimpl.NewMemoryInvitationStore()),
		sso.WithInvitationSender(sender),
		sso.WithTenantUserStore(defaultimpl.NewMemoryTenantUserStore()),
		sso.WithPermissionProvider(prov),
		sso.WithEmbedPermissionsInLogin(),
	)
	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	// Login (admin) — also exercises resolvePermissionsForLogin via embed.
	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("admin login = %d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no admin token: %v", out)
	}

	base := httpSrv.URL + "/api/v1/admin/tenants/org-9/invitations"

	// Send an invitation.
	status, sOut := rcovPostJSON(t, base, token, map[string]any{
		"email": "newhire@org-9.example", "role": "member",
	})
	if status != http.StatusAccepted && status != http.StatusOK {
		t.Fatalf("send invitation = %d body=%v", status, sOut)
	}
	if sender.token == "" || sender.email != "newhire@org-9.example" {
		t.Errorf("invitation not delivered: %+v", sender)
	}

	// List pending invitations (NEVER leaks the token value).
	status, lOut := rcovDo(t, http.MethodGet, base, token, nil)
	if status != http.StatusOK {
		t.Fatalf("list invitations = %d body=%v", status, lOut)
	}
	invs, _ := lOut["invitations"].([]any)
	if len(invs) != 1 {
		t.Errorf("invitations = %d, want 1 (body=%v)", len(invs), lOut)
	}

	// Send with a bad role => 400.
	status, _ = rcovPostJSON(t, base, token, map[string]any{
		"email": "x@org-9.example", "role": "not-a-real-role",
	})
	if status != http.StatusBadRequest {
		t.Errorf("send invitation bad role = %d, want 400", status)
	}

	// Send with no email => 400.
	status, _ = rcovPostJSON(t, base, token, map[string]any{"role": "member"})
	if status != http.StatusBadRequest {
		t.Errorf("send invitation no email = %d, want 400", status)
	}

	// Missing tenant id in the path is structurally impossible via the router,
	// but an unauthenticated caller is still rejected by the admin gate.
	status, _ = rcovPostJSON(t, base, "", map[string]any{"email": "y@org-9.example"})
	if status != http.StatusUnauthorized {
		t.Errorf("unauth send invitation = %d, want 401", status)
	}

	_ = time.Now
}

// TestRcov2AI_RevokeInvitation drives the admin revoke-invitation handler:
// send, revoke (204), list shows nothing pending, repeat revoke is still 204
// (idempotent — no pending-invitation oracle), and the admin gate rejects an
// unauthenticated caller.
func TestRcov2AI_RevokeInvitation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, "", []string{"root"})
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"root"})

	sender := &rcov2AdminInviteSender{}
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithInvitationStore(defaultimpl.NewMemoryInvitationStore()),
		sso.WithInvitationSender(sender),
		sso.WithTenantUserStore(defaultimpl.NewMemoryTenantUserStore()),
		sso.WithPermissionProvider(prov),
		sso.WithEmbedPermissionsInLogin(),
	)
	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	// Login (admin).
	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("admin login = %d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no admin token: %v", out)
	}

	base := httpSrv.URL + "/api/v1/admin/tenants/org-9/invitations"

	status, _ = rcovPostJSON(t, base, token, map[string]any{"email": "leaver@org-9.example", "role": "member"})
	if status != http.StatusAccepted {
		t.Fatalf("send invitation = %d", status)
	}
	status, _ = rcovDo(t, http.MethodDelete, base+"/leaver@org-9.example", token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("revoke invitation = %d, want 204", status)
	}
	status, lOut := rcovDo(t, http.MethodGet, base, token, nil)
	if invs, _ := lOut["invitations"].([]any); status != http.StatusOK || len(invs) != 0 {
		t.Errorf("list after revoke = %d/%d invites, want 200/0 (body=%v)", status, len(invs), lOut)
	}
	// Idempotent repeat -> still 204 (no pending-invitation oracle).
	status, _ = rcovDo(t, http.MethodDelete, base+"/leaver@org-9.example", token, nil)
	if status != http.StatusNoContent {
		t.Errorf("repeat revoke = %d, want 204", status)
	}
	// Unauthenticated -> admin gate 401.
	status, _ = rcovDo(t, http.MethodDelete, base+"/leaver@org-9.example", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("unauth revoke = %d, want 401", status)
	}
}
