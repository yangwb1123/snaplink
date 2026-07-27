package selfserviceaccount

import (
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Self-service B2B organization endpoints (the bearer subject's own org
// membership), extracted from package sso (root). The admin roster + invitation
// management handlers live in admin/tenants.go.

// orgMembershipJSON is the wire shape for a user's org membership.
type orgMembershipJSON struct {
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func orgMembershipToJSON(m *core.TenantMembership) orgMembershipJSON {
	return orgMembershipJSON{TenantID: m.TenantID, UserID: m.UserID, Role: string(m.Role), CreatedAt: m.CreatedAt}
}

// HandleMyOrganizations serves GET /me/organizations — the orgs the bearer
// subject belongs to. Credential-adjacent: no-store headers.
func HandleMyOrganizations(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	members, err := d.TenantUserStore().ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list my organizations failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	out := make([]orgMembershipJSON, 0, len(members))
	for _, m := range members {
		out = append(out, orgMembershipToJSON(m))
	}
	ctx.JSON(http.StatusOK, map[string]any{"organizations": out})
}

// HandleLeaveMyOrganization serves DELETE /me/organizations/:tenant_id — the
// authenticated user leaves an org without admin intervention. Idempotent
// (leaving a non-member org succeeds). Emits org_left.
func HandleLeaveMyOrganization(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	tenantID := ctx.Param("tenant_id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := d.TenantUserStore().Remove(ctx.Request().Context(), tenantID, userID); err != nil {
		d.Logger().Error("leave organization failed", "user_id", userID, "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if aud := d.Auditor(); aud != nil {
		evt := &audit.Event{Type: audit.EventOrgLeft, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		audit.SetMeta(evt, core.KeyTenantID, tenantID)
		aud.Record(ctx.Request().Context(), evt)
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleAcceptInvitation serves POST /me/invitations/accept — the authenticated
// subject redeems an invitation token and joins the invited org at the invited
// role. Body: {token}. Single-use (consumed). Oracle-safe: missing/expired/
// consumed token all collapse to one invitation_invalid. Emits
// invitation_accepted.
func HandleAcceptInvitation(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || req.Token == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvitationInvalid))
		return
	}
	rctx := ctx.Request().Context()
	inv, err := d.InvitationStore().Consume(rctx, req.Token)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvitationInvalid))
		return
	}
	if err := d.TenantUserStore().Add(rctx, &core.TenantMembership{
		TenantID: inv.TenantID, UserID: userID, Role: inv.Role, CreatedAt: time.Now(),
	}); err != nil {
		d.Logger().Error("accept invitation: add membership failed", "tenant_id", inv.TenantID, "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if aud := d.Auditor(); aud != nil {
		evt := &audit.Event{Type: audit.EventInvitationAccepted, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		audit.SetMeta(evt, core.KeyTenantID, inv.TenantID)
		aud.Record(rctx, evt)
	}
	ctx.JSON(http.StatusOK, map[string]any{"tenant_id": inv.TenantID, "role": string(inv.Role)})
}
