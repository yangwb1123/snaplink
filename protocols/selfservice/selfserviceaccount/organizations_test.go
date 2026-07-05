package selfserviceaccount

import (
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

func TestHandleMyOrganizations_ListsOwnMembershipsOnly(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.tenantUsers.Add(t.Context(), &core.TenantMembership{TenantID: "tenant-a", UserID: "user-1", Role: core.TenantRoleMember, CreatedAt: time.Now()})
	_ = d.tenantUsers.Add(t.Context(), &core.TenantMembership{TenantID: "tenant-b", UserID: "user-1", Role: core.TenantRoleAdmin, CreatedAt: time.Now()})
	_ = d.tenantUsers.Add(t.Context(), &core.TenantMembership{TenantID: "tenant-c", UserID: "someone-else", Role: core.TenantRoleMember, CreatedAt: time.Now()})

	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMyOrganizations(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	resp := decodeBody(t, rec)
	orgs, _ := resp["organizations"].([]any)
	if len(orgs) != 2 {
		t.Fatalf("got %d organizations, want 2 (own only)", len(orgs))
	}
}

func TestHandleLeaveMyOrganization(t *testing.T) {
	t.Parallel()
	t.Run("happy path", func(t *testing.T) {
		d := newTestDeps()
		_ = d.tenantUsers.Add(t.Context(), &core.TenantMembership{TenantID: "tenant-a", UserID: "user-1", Role: core.TenantRoleMember, CreatedAt: time.Now()})
		rec := servePath(http.MethodDelete, "/me/organizations/:tenant_id", "/me/organizations/tenant-a", "",
			func(ctx core.HandlerContext) { HandleLeaveMyOrganization(d, ctx) })
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204, body=%s", rec.Code, rec.Body.String())
		}
		members, _ := d.tenantUsers.ListByUser(t.Context(), "user-1")
		if len(members) != 0 {
			t.Error("membership should be removed")
		}
	})

	// Documented behavior: leaving a tenant the user never belonged to still
	// succeeds (Remove is idempotent) rather than 404ing.
	t.Run("idempotent for non-member", func(t *testing.T) {
		d := newTestDeps()
		rec := servePath(http.MethodDelete, "/me/organizations/:tenant_id", "/me/organizations/never-joined", "",
			func(ctx core.HandlerContext) { HandleLeaveMyOrganization(d, ctx) })
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (idempotent)", rec.Code)
		}
	})
}

func TestHandleAcceptInvitation_HappyPath(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	if err := d.invitations.Issue(t.Context(), &core.Invitation{
		Token: "invite-tok", TenantID: "tenant-a", Role: core.TenantRoleAdmin, ExpiresAt: futureExpiry(),
	}); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"invite-tok"}`)
	HandleAcceptInvitation(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBody(t, rec)
	if resp["tenant_id"] != "tenant-a" || resp["role"] != string(core.TenantRoleAdmin) {
		t.Fatalf("unexpected body: %v", resp)
	}
	m, err := d.tenantUsers.Get(t.Context(), "tenant-a", "user-1")
	if err != nil || m == nil {
		t.Fatalf("membership not created: %v", err)
	}
}

func TestHandleAcceptInvitation_InvalidToken(t *testing.T) {
	t.Parallel()
	cases := []string{`{"token":""}`, `{"token":"never-issued"}`}
	for _, body := range cases {
		d := newTestDeps()
		ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, body)
		HandleAcceptInvitation(d, ctx)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
		if got := decodeBody(t, rec)["error"]; got != core.ErrInvitationInvalid {
			t.Errorf("body %q: error = %v, want %s", body, got, core.ErrInvitationInvalid)
		}
	}
}

func TestHandleAcceptInvitation_ExpiredToken(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.invitations.Issue(t.Context(), &core.Invitation{
		Token: "invite-tok", TenantID: "tenant-a", Role: core.TenantRoleMember, ExpiresAt: pastExpiry(),
	})
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"token":"invite-tok"}`)
	HandleAcceptInvitation(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if _, err := d.tenantUsers.Get(t.Context(), "tenant-a", "user-1"); err == nil {
		t.Error("an expired invitation must not create a membership")
	}
}
