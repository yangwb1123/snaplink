package selfserviceaccount

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestValidTenantRole(t *testing.T) {
	valid := []core.TenantRole{core.TenantRoleMember, core.TenantRoleAdmin, core.TenantRoleGuest}
	for _, r := range valid {
		if !validTenantRole(r) {
			t.Errorf("validTenantRole(%q) = false, want true", r)
		}
	}
	for _, r := range []core.TenantRole{"", "owner", "Admin", "root"} {
		if validTenantRole(r) {
			t.Errorf("validTenantRole(%q) = true, want false", r)
		}
	}
}

func TestMintInviteToken_UniqueAndDecodable(t *testing.T) {
	a, err := mintInviteToken()
	if err != nil {
		t.Fatalf("mintInviteToken: %v", err)
	}
	b, err := mintInviteToken()
	if err != nil {
		t.Fatalf("mintInviteToken: %v", err)
	}
	if a == b {
		t.Fatalf("two mints returned the same token — not random")
	}
	// 32 random bytes, base64url, no padding — a live credential, so it must
	// carry full entropy.
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("token is not valid base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("token entropy = %d bytes, want 32", len(raw))
	}
}

// ---- org-admin handler test harness ----
//
// testhelpers_test.go's testDeps hardcodes TenantSuspended -> false and
// InvitationSender -> nil for every other handler test in this package, so
// they can't be toggled per-case there without disturbing those tests.
// orgAdminDeps embeds *testDeps and overrides just those two accessors,
// leaving every storage-backed dependency (the real Memory* stores) intact.

type orgAdminDeps struct {
	*testDeps
	suspendedTenant string
	invitationSend  spi.InvitationSender
}

func newOrgAdminDeps() *orgAdminDeps {
	return &orgAdminDeps{testDeps: newTestDeps()}
}

func (d *orgAdminDeps) TenantSuspended(_ context.Context, tenantID string) bool {
	return d.suspendedTenant != "" && tenantID == d.suspendedTenant
}

func (d *orgAdminDeps) InvitationSender() spi.InvitationSender { return d.invitationSend }

var _ Deps = (*orgAdminDeps)(nil)

// stubInvitationSender is a deterministic spi.InvitationSender that records
// each call's args so a test can assert what was sent without a real mailer.
type stubInvitationSender struct {
	calls []sentInvitation
	err   error
}

type sentInvitation struct{ email, tenantID, role, token string }

func (s *stubInvitationSender) SendInvitation(_ context.Context, email, tenantID, role, token string) error {
	if s.err != nil {
		return s.err
	}
	s.calls = append(s.calls, sentInvitation{email, tenantID, role, token})
	return nil
}

var _ spi.InvitationSender = (*stubInvitationSender)(nil)

// asUser returns a *testDeps that shares every real store with base but
// authenticates as a different subject — used to drive the SAME tenant's
// roster from two distinct "logged in as" admins in the concurrency test.
func asUser(base *testDeps, userID string) *testDeps {
	return &testDeps{
		users:         base.users,
		passwords:     base.passwords,
		sessions:      base.sessions,
		consents:      base.consents,
		tenantUsers:   base.tenantUsers,
		invitations:   base.invitations,
		identityLinks: base.identityLinks,
		mfaStore:      base.mfaStore,
		authSubject:   userID,
		authClaims:    &core.TokenClaims{Subject: userID},
	}
}

func seedMembership(t *testing.T, d *testDeps, tenantID, userID string, role core.TenantRole) {
	t.Helper()
	if err := d.tenantUsers.Add(t.Context(), &core.TenantMembership{
		TenantID: tenantID, UserID: userID, Role: role, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed membership %s/%s: %v", tenantID, userID, err)
	}
}

// ---- HandleOrgAdminListMembers ----

func TestHandleOrgAdminListMembers(t *testing.T) {
	t.Parallel()

	t.Run("happy path lists the whole roster", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)
		seedMembership(t, d.testDeps, "tenant-a", "user-2", core.TenantRoleMember)

		rec := servePath(http.MethodGet, "/me/organizations/:tenant_id/members", "/me/organizations/tenant-a/members", "",
			func(ctx core.HandlerContext) { HandleOrgAdminListMembers(d, ctx) })

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		resp := decodeBody(t, rec)
		members, _ := resp["members"].([]any)
		if len(members) != 2 {
			t.Fatalf("got %d members, want 2", len(members))
		}
	})

	t.Run("403 when caller is not a tenant admin", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleMember)

		rec := servePath(http.MethodGet, "/me/organizations/:tenant_id/members", "/me/organizations/tenant-a/members", "",
			func(ctx core.HandlerContext) { HandleOrgAdminListMembers(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrForbidden {
			t.Fatalf("error = %v, want %s", got, core.ErrForbidden)
		}
	})

	t.Run("works even when the org is suspended (reads are never gated)", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		d.suspendedTenant = "tenant-a"
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		rec := servePath(http.MethodGet, "/me/organizations/:tenant_id/members", "/me/organizations/tenant-a/members", "",
			func(ctx core.HandlerContext) { HandleOrgAdminListMembers(d, ctx) })

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (reads not suspension-gated)", rec.Code)
		}
	})
}

// ---- HandleOrgAdminPutMember ----

func putMemberPath(tenantID, userID string) (string, string) {
	return "/me/organizations/:tenant_id/members/:user_id", "/me/organizations/" + tenantID + "/members/" + userID
}

func TestHandleOrgAdminPutMember(t *testing.T) {
	t.Parallel()

	t.Run("happy path grants co-admin", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)
		seedMembership(t, d.testDeps, "tenant-a", "user-2", core.TenantRoleMember)

		pattern, path := putMemberPath("tenant-a", "user-2")
		rec := servePath(http.MethodPut, pattern, path, `{"role":"admin"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminPutMember(d, ctx) })

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		m, err := d.tenantUsers.Get(t.Context(), "tenant-a", "user-2")
		if err != nil || m.Role != core.TenantRoleAdmin {
			t.Fatalf("role not updated: m=%v err=%v", m, err)
		}
	})

	t.Run("403 when caller is not a tenant admin", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleMember)
		seedMembership(t, d.testDeps, "tenant-a", "user-2", core.TenantRoleMember)

		pattern, path := putMemberPath("tenant-a", "user-2")
		rec := servePath(http.MethodPut, pattern, path, `{"role":"admin"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminPutMember(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("404 when target is not a member", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		pattern, path := putMemberPath("tenant-a", "ghost")
		rec := servePath(http.MethodPut, pattern, path, `{"role":"member"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminPutMember(d, ctx) })

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("409 last_org_admin refuses demoting the sole admin", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		pattern, path := putMemberPath("tenant-a", "user-1")
		rec := servePath(http.MethodPut, pattern, path, `{"role":"member"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminPutMember(d, ctx) })

		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrLastOrgAdmin {
			t.Fatalf("error = %v, want %s", got, core.ErrLastOrgAdmin)
		}
		m, err := d.tenantUsers.Get(t.Context(), "tenant-a", "user-1")
		if err != nil || m.Role != core.TenantRoleAdmin {
			t.Fatalf("sole admin's role must be unchanged: m=%v err=%v", m, err)
		}
	})

	t.Run("demoting one of two admins succeeds", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)
		seedMembership(t, d.testDeps, "tenant-a", "user-2", core.TenantRoleAdmin)

		pattern, path := putMemberPath("tenant-a", "user-2")
		rec := servePath(http.MethodPut, pattern, path, `{"role":"member"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminPutMember(d, ctx) })

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (not the last admin), body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("403 when the org is suspended", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		d.suspendedTenant = "tenant-a"
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)
		seedMembership(t, d.testDeps, "tenant-a", "user-2", core.TenantRoleMember)

		pattern, path := putMemberPath("tenant-a", "user-2")
		rec := servePath(http.MethodPut, pattern, path, `{"role":"admin"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminPutMember(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrAccessDenied {
			t.Fatalf("error = %v, want %s", got, core.ErrAccessDenied)
		}
	})
}

// ---- HandleOrgAdminRemoveMember ----

func removeMemberPath(tenantID, userID string) (string, string) {
	return "/me/organizations/:tenant_id/members/:user_id", "/me/organizations/" + tenantID + "/members/" + userID
}

func TestHandleOrgAdminRemoveMember(t *testing.T) {
	t.Parallel()

	t.Run("happy path removes a member", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)
		seedMembership(t, d.testDeps, "tenant-a", "user-2", core.TenantRoleMember)

		pattern, path := removeMemberPath("tenant-a", "user-2")
		rec := servePath(http.MethodDelete, pattern, path, "",
			func(ctx core.HandlerContext) { HandleOrgAdminRemoveMember(d, ctx) })

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204, body=%s", rec.Code, rec.Body.String())
		}
		if _, err := d.tenantUsers.Get(t.Context(), "tenant-a", "user-2"); err == nil {
			t.Error("membership should be removed")
		}
	})

	t.Run("403 when caller is not a tenant admin", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleMember)
		seedMembership(t, d.testDeps, "tenant-a", "user-2", core.TenantRoleMember)

		pattern, path := removeMemberPath("tenant-a", "user-2")
		rec := servePath(http.MethodDelete, pattern, path, "",
			func(ctx core.HandlerContext) { HandleOrgAdminRemoveMember(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("404-equivalent: idempotent for an absent target", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		pattern, path := removeMemberPath("tenant-a", "ghost")
		rec := servePath(http.MethodDelete, pattern, path, "",
			func(ctx core.HandlerContext) { HandleOrgAdminRemoveMember(d, ctx) })

		// Documented behavior (see HandleOrgAdminRemoveMember doc comment):
		// removing a non-admin absent member is idempotent, not a 404 — a
		// non-admin target can never be "the last admin" either.
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (idempotent)", rec.Code)
		}
	})

	t.Run("409 last_org_admin refuses removing the sole admin", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		pattern, path := removeMemberPath("tenant-a", "user-1")
		rec := servePath(http.MethodDelete, pattern, path, "",
			func(ctx core.HandlerContext) { HandleOrgAdminRemoveMember(d, ctx) })

		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrLastOrgAdmin {
			t.Fatalf("error = %v, want %s", got, core.ErrLastOrgAdmin)
		}
		if _, err := d.tenantUsers.Get(t.Context(), "tenant-a", "user-1"); err != nil {
			t.Fatalf("sole admin must remain a member: %v", err)
		}
	})

	t.Run("403 when the org is suspended", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		d.suspendedTenant = "tenant-a"
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)
		seedMembership(t, d.testDeps, "tenant-a", "user-2", core.TenantRoleMember)

		pattern, path := removeMemberPath("tenant-a", "user-2")
		rec := servePath(http.MethodDelete, pattern, path, "",
			func(ctx core.HandlerContext) { HandleOrgAdminRemoveMember(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})
}

// ---- HandleOrgAdminSendInvitation ----

func TestHandleOrgAdminSendInvitation(t *testing.T) {
	t.Parallel()

	t.Run("happy path issues and delivers a token", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		sender := &stubInvitationSender{}
		d.invitationSend = sender
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		rec := servePath(http.MethodPost, "/me/organizations/:tenant_id/invitations", "/me/organizations/tenant-a/invitations",
			`{"email":"new@example.com","role":"member"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminSendInvitation(d, ctx) })

		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
		}
		if len(sender.calls) != 1 {
			t.Fatalf("sender called %d times, want 1", len(sender.calls))
		}
		call := sender.calls[0]
		if call.email != "new@example.com" || call.tenantID != "tenant-a" || call.role != "member" || call.token == "" {
			t.Fatalf("unexpected send call: %+v", call)
		}
	})

	t.Run("403 when caller is not a tenant admin", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		d.invitationSend = &stubInvitationSender{}
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleMember)

		rec := servePath(http.MethodPost, "/me/organizations/:tenant_id/invitations", "/me/organizations/tenant-a/invitations",
			`{"email":"new@example.com"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminSendInvitation(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("501 when no InvitationSender is wired", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps() // invitationSend left nil
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		rec := servePath(http.MethodPost, "/me/organizations/:tenant_id/invitations", "/me/organizations/tenant-a/invitations",
			`{"email":"new@example.com"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminSendInvitation(d, ctx) })

		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("status = %d, want 501", rec.Code)
		}
	})

	t.Run("403 when the org is suspended", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		d.invitationSend = &stubInvitationSender{}
		d.suspendedTenant = "tenant-a"
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		rec := servePath(http.MethodPost, "/me/organizations/:tenant_id/invitations", "/me/organizations/tenant-a/invitations",
			`{"email":"new@example.com"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminSendInvitation(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})
}

// ---- HandleOrgAdminListInvitations ----

func TestHandleOrgAdminListInvitations(t *testing.T) {
	t.Parallel()

	t.Run("happy path lists pending invitations without the token", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)
		if err := d.invitations.Issue(t.Context(), &core.Invitation{
			Token: "tok-1", TenantID: "tenant-a", Email: "pending@example.com",
			Role: core.TenantRoleMember, ExpiresAt: futureExpiry(),
		}); err != nil {
			t.Fatalf("seed invitation: %v", err)
		}

		rec := servePath(http.MethodGet, "/me/organizations/:tenant_id/invitations", "/me/organizations/tenant-a/invitations", "",
			func(ctx core.HandlerContext) { HandleOrgAdminListInvitations(d, ctx) })

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		bodyStr := rec.Body.String() // capture before decodeBody drains rec.Body
		resp := decodeBody(t, rec)
		invs, _ := resp["invitations"].([]any)
		if len(invs) != 1 {
			t.Fatalf("got %d invitations, want 1", len(invs))
		}
		entry, _ := invs[0].(map[string]any)
		if entry["email"] != "pending@example.com" {
			t.Errorf("invitation email = %v, want pending@example.com", entry["email"])
		}
		if strings.Contains(bodyStr, "tok-1") {
			t.Error("response must never include the invitation token")
		}
	})

	t.Run("403 when caller is not a tenant admin", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleMember)

		rec := servePath(http.MethodGet, "/me/organizations/:tenant_id/invitations", "/me/organizations/tenant-a/invitations", "",
			func(ctx core.HandlerContext) { HandleOrgAdminListInvitations(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})
}

// ---- HandleOrgAdminRevokeInvitation ----

func TestHandleOrgAdminRevokeInvitation(t *testing.T) {
	t.Parallel()

	t.Run("happy path revokes the pending invitation", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)
		if err := d.invitations.Issue(t.Context(), &core.Invitation{
			Token: "tok-1", TenantID: "tenant-a", Email: "pending@example.com",
			Role: core.TenantRoleMember, ExpiresAt: futureExpiry(),
		}); err != nil {
			t.Fatalf("seed invitation: %v", err)
		}

		rec := servePath(http.MethodDelete, "/me/organizations/:tenant_id/invitations/:email",
			"/me/organizations/tenant-a/invitations/pending@example.com", "",
			func(ctx core.HandlerContext) { HandleOrgAdminRevokeInvitation(d, ctx) })

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204, body=%s", rec.Code, rec.Body.String())
		}
		invs, err := d.invitations.ListByTenant(t.Context(), "tenant-a")
		if err != nil {
			t.Fatalf("ListByTenant: %v", err)
		}
		if len(invs) != 0 {
			t.Errorf("invitation should be revoked, got %d pending", len(invs))
		}
	})

	t.Run("idempotent for a non-pending recipient", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		rec := servePath(http.MethodDelete, "/me/organizations/:tenant_id/invitations/:email",
			"/me/organizations/tenant-a/invitations/never-invited@example.com", "",
			func(ctx core.HandlerContext) { HandleOrgAdminRevokeInvitation(d, ctx) })

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (idempotent, no oracle)", rec.Code)
		}
	})

	t.Run("403 when caller is not a tenant admin", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleMember)

		rec := servePath(http.MethodDelete, "/me/organizations/:tenant_id/invitations/:email",
			"/me/organizations/tenant-a/invitations/pending@example.com", "",
			func(ctx core.HandlerContext) { HandleOrgAdminRevokeInvitation(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("403 when the org is suspended", func(t *testing.T) {
		t.Parallel()
		d := newOrgAdminDeps()
		d.suspendedTenant = "tenant-a"
		seedMembership(t, d.testDeps, "tenant-a", "user-1", core.TenantRoleAdmin)

		rec := servePath(http.MethodDelete, "/me/organizations/:tenant_id/invitations/:email",
			"/me/organizations/tenant-a/invitations/pending@example.com", "",
			func(ctx core.HandlerContext) { HandleOrgAdminRevokeInvitation(d, ctx) })

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	})
}

// ---- Concurrency regression: check-then-act must be atomic per tenant ----
//
// Reproduces the bug directly: a tenant with exactly two admins (X, Y), one
// request demoting/removing X and another concurrently demoting/removing Y.
// Before the per-tenant lock, both requests could independently observe "the
// other admin still exists" and both proceed, leaving zero admins. Run with
// -race -count=10+ to catch both the data race and the logical race.

func TestHandleOrgAdminRemoveMember_ConcurrentRemovalNeverZerosAdmins(t *testing.T) {
	base := newTestDeps()
	tenantID := "race-tenant-remove"
	seedMembership(t, base, tenantID, "admin-x", core.TenantRoleAdmin)
	seedMembership(t, base, tenantID, "admin-y", core.TenantRoleAdmin)

	dX := asUser(base, "admin-x")
	dY := asUser(base, "admin-y")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pattern, path := removeMemberPath(tenantID, "admin-y")
		servePath(http.MethodDelete, pattern, path, "",
			func(ctx core.HandlerContext) { HandleOrgAdminRemoveMember(dX, ctx) })
	}()
	go func() {
		defer wg.Done()
		pattern, path := removeMemberPath(tenantID, "admin-x")
		servePath(http.MethodDelete, pattern, path, "",
			func(ctx core.HandlerContext) { HandleOrgAdminRemoveMember(dY, ctx) })
	}()
	wg.Wait()

	members, err := base.tenantUsers.ListByTenant(t.Context(), tenantID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	admins := 0
	for _, m := range members {
		if m.Role == core.TenantRoleAdmin {
			admins++
		}
	}
	if admins == 0 {
		t.Fatalf("race: tenant ended up with zero admins, members=%v", members)
	}
}

func TestHandleOrgAdminPutMember_ConcurrentDemotionNeverZerosAdmins(t *testing.T) {
	base := newTestDeps()
	tenantID := "race-tenant-demote"
	seedMembership(t, base, tenantID, "admin-x", core.TenantRoleAdmin)
	seedMembership(t, base, tenantID, "admin-y", core.TenantRoleAdmin)

	dX := asUser(base, "admin-x")
	dY := asUser(base, "admin-y")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pattern, path := putMemberPath(tenantID, "admin-y")
		servePath(http.MethodPut, pattern, path, `{"role":"member"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminPutMember(dX, ctx) })
	}()
	go func() {
		defer wg.Done()
		pattern, path := putMemberPath(tenantID, "admin-x")
		servePath(http.MethodPut, pattern, path, `{"role":"member"}`,
			func(ctx core.HandlerContext) { HandleOrgAdminPutMember(dY, ctx) })
	}()
	wg.Wait()

	members, err := base.tenantUsers.ListByTenant(t.Context(), tenantID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	admins := 0
	for _, m := range members {
		if m.Role == core.TenantRoleAdmin {
			admins++
		}
	}
	if admins == 0 {
		t.Fatalf("race: tenant ended up with zero admins, members=%v", members)
	}
}
