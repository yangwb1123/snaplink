package admin

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// B2B tenant-membership (admin roster) + email-invitation (send/list) handlers,
// extracted from package sso (root) into the admin domain. The self-service
// /me organization endpoints live in selfservice/organizations.go.

// membershipJSON is the wire shape for B2B org membership.
type membershipJSON struct {
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func membershipToJSON(m *core.TenantMembership) membershipJSON {
	return membershipJSON{TenantID: m.TenantID, UserID: m.UserID, Role: string(m.Role), CreatedAt: m.CreatedAt}
}

func validTenantRole(r core.TenantRole) bool {
	return r == core.TenantRoleMember || r == core.TenantRoleAdmin || r == core.TenantRoleGuest
}

// invitationTTL bounds how long an org invitation token is valid.
const invitationTTL = 7 * 24 * time.Hour

// HandleAdminListTenantMembers serves GET /api/v1/admin/tenants/:id/members —
// the org roster. admin:read.
func HandleAdminListTenantMembers(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	members, err := d.TenantUserStore().ListByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		d.Logger().Error("admin list tenant members failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	out := make([]membershipJSON, 0, len(members))
	for _, m := range members {
		out = append(out, membershipToJSON(m))
	}
	ctx.JSON(http.StatusOK, map[string]any{"members": out})
}

// HandleAdminPutTenantMember serves PUT /api/v1/admin/tenants/:id/members/:user_id
// — add a user to an org or change their org role. admin:write. Body: {role}
// (member|admin|guest; defaults to member). Idempotent (upsert). Emits
// admin_tenant_member_added.
func HandleAdminPutTenantMember(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("id")
	userID := ctx.Param("user_id")
	if tenantID == "" || userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	_ = oauth.BindParams(ctx, &req)
	role := core.TenantRole(req.Role)
	if role == "" {
		role = core.TenantRoleMember
	}
	if !validTenantRole(role) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := d.TenantUserStore().Add(ctx.Request().Context(), &core.TenantMembership{
		TenantID: tenantID, UserID: userID, Role: role, CreatedAt: time.Now(),
	}); err != nil {
		d.Logger().Error("admin add tenant member failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminTenantMemberAdded, userID, core.KeyTenantID, tenantID)
	ctx.JSON(http.StatusOK, map[string]any{"tenant_id": tenantID, "user_id": userID, "role": string(role)})
}

// HandleAdminRemoveTenantMember serves DELETE /api/v1/admin/tenants/:id/members/:user_id
// — remove a user from an org. admin:write. Idempotent. Emits
// admin_tenant_member_removed.
func HandleAdminRemoveTenantMember(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("id")
	userID := ctx.Param("user_id")
	if tenantID == "" || userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := d.TenantUserStore().Remove(ctx.Request().Context(), tenantID, userID); err != nil {
		d.Logger().Error("admin remove tenant member failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminTenantMemberRemoved, userID, core.KeyTenantID, tenantID)
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleAdminSendInvitation serves POST /api/v1/admin/tenants/:id/invitations —
// mint + deliver a single-use org invitation. admin:write. Body: {email, role}
// (role member|admin|guest, default member). 501 when no InvitationSender is
// wired (the token must never be returned in the response). Emits
// invitation_sent (never the token/email). Returns 202.
func HandleAdminSendInvitation(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || strings.TrimSpace(req.Email) == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	role := core.TenantRole(req.Role)
	if role == "" {
		role = core.TenantRoleMember
	}
	if !validTenantRole(role) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if d.InvitationSender() == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotFound))
		return
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	rctx := ctx.Request().Context()
	if err := d.InvitationStore().Issue(rctx, &core.Invitation{
		Token: token, TenantID: tenantID, Email: strings.TrimSpace(req.Email), Role: role,
		ExpiresAt: time.Now().Add(invitationTTL),
	}); err != nil {
		d.Logger().Error("issue invitation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if err := d.InvitationSender().SendInvitation(rctx, strings.TrimSpace(req.Email), tenantID, string(role), token); err != nil {
		d.Logger().Error("send invitation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventInvitationSent, "", core.KeyTenantID, tenantID)
	ctx.JSON(http.StatusAccepted, map[string]any{"status": "sent"})
}

// HandleAdminListInvitations serves GET /api/v1/admin/tenants/:id/invitations —
// pending org invitations. admin:read. NEVER returns the token value — only
// email + role + expiry.
func HandleAdminListInvitations(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	invs, err := d.InvitationStore().ListByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		d.Logger().Error("list invitations failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	out := make([]map[string]any, 0, len(invs))
	for _, inv := range invs {
		out = append(out, map[string]any{
			"email": inv.Email, "role": string(inv.Role),
			"expires_at": inv.ExpiresAt, "expired": inv.IsExpired(),
		})
	}
	ctx.JSON(http.StatusOK, map[string]any{"invitations": out})
}
