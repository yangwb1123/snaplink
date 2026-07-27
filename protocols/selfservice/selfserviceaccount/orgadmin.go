package selfserviceaccount

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Delegated org-admin surface (w2.11): /me/organizations/:tenant_id/{members,
// invitations}. A TenantRoleAdmin of tenant X manages ONLY tenant X's roster +
// invitations via the subject bearer, WITHOUT the platform-wide admin scope.
// It mirrors the platform-admin roster logic in admin/tenants.go but swaps the
// gate (global scope -> tenant-admin membership) and derives the actor from the
// subject bearer. The wire member shape (orgMembershipJSON) is shared with
// organizations.go in this package.

// orgInvitationTTL bounds how long a delegated-admin invitation token is valid.
// Matches the platform-admin invitationTTL so both send paths behave alike.
const orgInvitationTTL = 7 * 24 * time.Hour

// Audit metadata stamped on every delegated-admin action so a delegated action
// is distinguishable from a platform-admin one (bounded cardinality — a fixed
// key + value pair, never per-request data). Held as consts so the handlers and
// their tests cannot drift.
const (
	auditMetaVia         = "via"
	auditMetaViaOrgAdmin = "org_admin"
)

func validTenantRole(r core.TenantRole) bool {
	return r == core.TenantRoleMember || r == core.TenantRoleAdmin || r == core.TenantRoleGuest
}

// forbid writes the single, identical 403 the delegated org-admin gate uses for
// EVERY authorization failure. Centralizing it guarantees the three gate-fail
// cases (tenant-absent, not-a-member, member-but-not-admin) are byte-identical
// on the wire — no branch reveals which condition failed (anti-enumeration).
func forbid(d Deps, ctx core.HandlerContext) {
	ctx.JSON(http.StatusForbidden, d.ErrorBody(core.ErrForbidden))
}

// requireTenantAdmin is the SINGLE authorization choke point for the delegated
// org-admin surface: it proves the bearer subject is a TenantRoleAdmin OF the
// path tenant and returns the subject. FAIL-CLOSED — any outcome that does not
// affirmatively prove admin (missing membership, wrong role, or a store error)
// denies with the identical 403. tenantID comes ONLY from the path and
// membership is the SOLE gate (a tenant admin may manage from any host, so there
// is no cross-check against the resolved request tenant). Credential-adjacent:
// no-store headers at entry; a bad/absent bearer yields the oracle-safe 401
// challenge via MeSubjectOrChallenge.
func requireTenantAdmin(d Deps, ctx core.HandlerContext, tenantID string) (string, bool) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return "", false
	}
	if tenantID == "" {
		forbid(d, ctx)
		return "", false
	}
	m, err := d.TenantUserStore().Get(ctx.Request().Context(), tenantID, userID)
	if err != nil || m == nil || m.Role != core.TenantRoleAdmin {
		// A genuine store outage is logged (server-side only, never on the wire)
		// but STILL denies — fail-closed authorization. ErrNoMembership is the
		// expected "not a member" path and is not logged.
		if err != nil && !errors.Is(err, core.ErrNoMembership) {
			d.Logger().Error("org admin gate: membership lookup failed", "tenant_id", tenantID, "error", err)
		}
		forbid(d, ctx)
		return "", false
	}
	return userID, true
}

// refuseIfSuspended blocks a MUTATION when the org is suspended (reads are never
// gated). Returns true after writing the response — the caller must return.
// FAIL-OPEN on a suspension-store outage (TenantSuspended reports false),
// matching every other write path so an availability blip does not freeze admin
// operations. The proven admin already knows the org exists, so a distinct
// governance code here is no oracle.
func refuseIfSuspended(d Deps, ctx core.HandlerContext, tenantID string) bool {
	if d.TenantSuspended(ctx.Request().Context(), tenantID) {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(core.ErrAccessDenied))
		return true
	}
	return false
}

// recordOrgAdminAction emits a delegated-admin audit event. It reuses the
// platform EventAdminTenantMember*/Invitation* consts (no new event types) but
// with ActorID = the delegated admin's SUBJECT (NOT admin.ActorFromContext,
// which is empty on subject-bearer /me requests) and via=org_admin so the log
// distinguishes delegated from platform-admin actions. The invitation token is
// NEVER recorded.
func recordOrgAdminAction(d Deps, ctx core.HandlerContext, evtType audit.EventType, actorID, tenantID string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	evt := &audit.Event{
		Type:    evtType,
		Outcome: audit.OutcomeSuccess,
		ActorID: actorID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, core.KeyTenantID, tenantID)
	audit.SetMeta(evt, auditMetaVia, auditMetaViaOrgAdmin)
	aud.Record(ctx.Request().Context(), evt)
}

// isLastAdmin reports whether targetID is the ONLY admin of tenantID. Counting
// admins needs a ListByTenant scan (the store exposes no count primitive), which
// is acceptable for the small-N org-roster case. A non-admin target is never
// "the last admin", so this never blocks a normal member change.
func isLastAdmin(d Deps, ctx context.Context, tenantID, targetID string) (bool, error) {
	members, err := d.TenantUserStore().ListByTenant(ctx, tenantID)
	if err != nil {
		return false, err
	}
	admins := 0
	targetIsAdmin := false
	for _, m := range members {
		if m.Role != core.TenantRoleAdmin {
			continue
		}
		admins++
		if m.UserID == targetID {
			targetIsAdmin = true
		}
	}
	return targetIsAdmin && admins == 1, nil
}

// guardLastAdminDemotion refuses (409 last_org_admin) a role change that would
// strip the org's LAST admin (incl. self-demotion). Returns true after writing a
// response — the caller must return. A no-op unless the target is currently an
// admin being changed to a non-admin role.
func guardLastAdminDemotion(d Deps, ctx core.HandlerContext, tenantID, targetID string, current, next core.TenantRole) bool {
	if current != core.TenantRoleAdmin || next == core.TenantRoleAdmin {
		return false
	}
	last, err := isLastAdmin(d, ctx.Request().Context(), tenantID, targetID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return true
	}
	if last {
		ctx.JSON(http.StatusConflict, d.ErrorBody(core.ErrLastOrgAdmin))
		return true
	}
	return false
}

// bindRole parses the {role} body (form or JSON), defaulting to member and
// rejecting an unknown value with 400. Returns ok=false after writing the error.
func bindRole(d Deps, ctx core.HandlerContext) (core.TenantRole, bool) {
	var req struct {
		Role string `json:"role"`
	}
	_ = oauth.BindParams(ctx, &req)
	role := core.TenantRole(req.Role)
	if role == "" {
		role = core.TenantRoleMember
	}
	if !validTenantRole(role) {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return "", false
	}
	return role, true
}

// bindInvite parses the {email, role} body for an invitation, trimming the email
// and defaulting role to member. Returns ok=false after writing the 400.
func bindInvite(d Deps, ctx core.HandlerContext) (string, core.TenantRole, bool) {
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || strings.TrimSpace(req.Email) == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return "", "", false
	}
	role := core.TenantRole(req.Role)
	if role == "" {
		role = core.TenantRoleMember
	}
	if !validTenantRole(role) {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return "", "", false
	}
	return strings.TrimSpace(req.Email), role, true
}

// mintInviteToken generates the opaque single-use invitation token (32 random
// bytes, base64url). It is a live credential — delivered out-of-band, never
// returned in a response.
func mintInviteToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// HandleOrgAdminListMembers serves GET /me/organizations/:tenant_id/members —
// the roster of the caller's own org. Read; not suspension-gated.
func HandleOrgAdminListMembers(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("tenant_id")
	if _, ok := requireTenantAdmin(d, ctx, tenantID); !ok {
		return
	}
	members, err := d.TenantUserStore().ListByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		d.Logger().Error("org admin list members failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	out := make([]orgMembershipJSON, 0, len(members))
	for _, m := range members {
		out = append(out, orgMembershipToJSON(m))
	}
	ctx.JSON(http.StatusOK, map[string]any{"members": out})
}

// HandleOrgAdminPutMember serves PUT /me/organizations/:tenant_id/members/:user_id
// — change an EXISTING member's org role (co-admin grant allowed). Invite-only
// growth: a non-member target is 404, never a direct add. Refused on a suspended
// org; refused (409) when it would demote the last admin. Emits
// admin_tenant_member_added (via=org_admin).
func HandleOrgAdminPutMember(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("tenant_id")
	adminID, ok := requireTenantAdmin(d, ctx, tenantID)
	if !ok {
		return
	}
	if refuseIfSuspended(d, ctx, tenantID) {
		return
	}
	role, ok := bindRole(d, ctx)
	if !ok {
		return
	}
	targetID := ctx.Param("user_id")
	rctx := ctx.Request().Context()
	existing, err := d.TenantUserStore().Get(rctx, tenantID, targetID)
	if err != nil || existing == nil {
		// The proven admin is entitled to see org-internal membership, so a
		// non-member target is a plain 404, not the uniform gate 403.
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	if guardLastAdminDemotion(d, ctx, tenantID, targetID, existing.Role, role) {
		return
	}
	if err := d.TenantUserStore().Add(rctx, &core.TenantMembership{
		TenantID: tenantID, UserID: targetID, Role: role, CreatedAt: existing.CreatedAt,
	}); err != nil {
		d.Logger().Error("org admin put member failed", "tenant_id", tenantID, "user_id", targetID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordOrgAdminAction(d, ctx, audit.EventAdminTenantMemberAdded, adminID, tenantID)
	ctx.JSON(http.StatusOK, map[string]any{"tenant_id": tenantID, "user_id": targetID, "role": string(role)})
}

// HandleOrgAdminRemoveMember serves DELETE /me/organizations/:tenant_id/members/:user_id
// — remove a member from the caller's own org. Refused on a suspended org;
// refused (409) when it would remove the last admin (incl. self). Idempotent for
// a non-admin absent member. Emits admin_tenant_member_removed (via=org_admin).
func HandleOrgAdminRemoveMember(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("tenant_id")
	adminID, ok := requireTenantAdmin(d, ctx, tenantID)
	if !ok {
		return
	}
	if refuseIfSuspended(d, ctx, tenantID) {
		return
	}
	targetID := ctx.Param("user_id")
	rctx := ctx.Request().Context()
	last, err := isLastAdmin(d, rctx, tenantID, targetID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if last {
		ctx.JSON(http.StatusConflict, d.ErrorBody(core.ErrLastOrgAdmin))
		return
	}
	if err := d.TenantUserStore().Remove(rctx, tenantID, targetID); err != nil {
		d.Logger().Error("org admin remove member failed", "tenant_id", tenantID, "user_id", targetID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordOrgAdminAction(d, ctx, audit.EventAdminTenantMemberRemoved, adminID, tenantID)
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleOrgAdminSendInvitation serves POST /me/organizations/:tenant_id/invitations
// — mint + deliver a single-use invitation for the caller's own org. Refused on
// a suspended org. 501 when no InvitationSender is wired (the token must never be
// returned in a response). Emits invitation_sent (never the token/email).
func HandleOrgAdminSendInvitation(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("tenant_id")
	adminID, ok := requireTenantAdmin(d, ctx, tenantID)
	if !ok {
		return
	}
	if refuseIfSuspended(d, ctx, tenantID) {
		return
	}
	email, role, ok := bindInvite(d, ctx)
	if !ok {
		return
	}
	if d.InvitationSender() == nil {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrNotFound))
		return
	}
	token, err := mintInviteToken()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	rctx := ctx.Request().Context()
	if err := d.InvitationStore().Issue(rctx, &core.Invitation{
		Token: token, TenantID: tenantID, Email: email, Role: role,
		ExpiresAt: time.Now().Add(orgInvitationTTL),
	}); err != nil {
		d.Logger().Error("org admin issue invitation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if err := d.InvitationSender().SendInvitation(rctx, email, tenantID, string(role), token); err != nil {
		d.Logger().Error("org admin send invitation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordOrgAdminAction(d, ctx, audit.EventInvitationSent, adminID, tenantID)
	ctx.JSON(http.StatusAccepted, map[string]any{"status": "sent"})
}

// HandleOrgAdminListInvitations serves GET /me/organizations/:tenant_id/invitations
// — pending invitations for the caller's own org. Read; not suspension-gated.
// NEVER returns the token value — only email + role + expiry.
func HandleOrgAdminListInvitations(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("tenant_id")
	if _, ok := requireTenantAdmin(d, ctx, tenantID); !ok {
		return
	}
	invs, err := d.InvitationStore().ListByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		d.Logger().Error("org admin list invitations failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
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

// HandleOrgAdminRevokeInvitation serves DELETE
// /me/organizations/:tenant_id/invitations/:email — revoke every pending
// invitation for a recipient in the caller's own org. Refused on a suspended
// org. Idempotent (204 whether or not anything was pending — no oracle). Emits
// invitation_revoked (via=org_admin).
func HandleOrgAdminRevokeInvitation(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("tenant_id")
	adminID, ok := requireTenantAdmin(d, ctx, tenantID)
	if !ok {
		return
	}
	if refuseIfSuspended(d, ctx, tenantID) {
		return
	}
	email := ctx.Param("email")
	if email == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := d.InvitationStore().Revoke(ctx.Request().Context(), tenantID, email); err != nil {
		d.Logger().Error("org admin revoke invitation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordOrgAdminAction(d, ctx, audit.EventInvitationRevoked, adminID, tenantID)
	ctx.JSON(http.StatusNoContent, nil)
}
