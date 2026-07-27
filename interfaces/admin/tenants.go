package admin

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
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

// HandleAdminRevokeInvitation serves DELETE /api/v1/admin/tenants/:id/invitations/:email
// — revoke every pending invitation for a recipient. admin:write. Idempotent
// (204 whether or not anything was pending — no pending-invitation oracle).
// Emits invitation_revoked (never the token/email).
func HandleAdminRevokeInvitation(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("id")
	email := ctx.Param("email")
	if tenantID == "" || email == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := d.InvitationStore().Revoke(ctx.Request().Context(), tenantID, email); err != nil {
		d.Logger().Error("revoke invitation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventInvitationRevoked, "", core.KeyTenantID, tenantID)
	ctx.JSON(http.StatusNoContent, nil)
}

// Tenant-scoped offboarding/migration export (w2.14) — the admin-triggered
// sibling of the GDPR Art. 15 subject export in cmd/sso-server/
// compliance_routes.go, but scoped to a whole tenant (clients, roster,
// connections, permissions, session + audit summaries) instead of one
// subject. See protocols/compliance.TenantExporter for the assembly.

// tenantExportFilenameLayout is fixed-width (mirrors interfaces/sso's
// backupStampLayout) so the Content-Disposition filename sorts
// chronologically alongside other exports an admin downloads over time.
const tenantExportFilenameLayout = "20060102T150405Z"

// HandleAdminExportTenant serves POST /api/v1/admin/tenants/:id/export.
// admin:write — deliberately above the GET-default admin:read (see
// core.PathAdminTenantExport's doc comment): assembling this bundle is a
// heavier, more sensitive read than the roster/connection GETs, closer in
// kind to the backup trigger than to a plain list. Responds with the full
// bundle as a downloadable JSON attachment; a partial (best-effort) bundle
// still returns 207 so an admin notices without losing what DID export.
// Emits admin_tenant_exported.
func HandleAdminExportTenant(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if tenantRequestMismatch(ctx, tenantID) {
		ctx.JSON(http.StatusForbidden, core.ErrorBody(core.ErrTenantMismatch))
		return
	}

	exporter := &compliance.TenantExporter{
		Clients:     d.ClientStore(),
		Users:       d.UserProvider(),
		Sessions:    d.SessionManager(),
		Memberships: d.TenantUserStore(),
		Invitations: d.InvitationStore(),
		Connections: d.ConnectionStore(),
		Permissions: d.Permissions(),
		Auditor:     d.Auditor(),
	}
	bundle, err := exporter.BuildTenantExport(ctx.Request().Context(), tenantID)
	recordAdminTenantExport(d, ctx, tenantID, err)

	filename := "tenant-" + tenantID + "-export-" + bundle.GeneratedAt.Format(tenantExportFilenameLayout) + ".json"
	ctx.ResponseWriter().Header().Set(core.HeaderContentDisposition, `attachment; filename="`+filename+`"`)
	code := http.StatusOK
	if err != nil {
		// Best-effort: a failing store doesn't erase the sections that DID
		// export (see TenantExporter.BuildTenantExport's doc comment) —
		// 207 surfaces the partial result without hiding it as a plain 200.
		code = http.StatusMultiStatus
	}
	ctx.JSON(code, bundle)
}

// tenantRequestMismatch reports whether this request resolved a HOST-based
// tenant (domains/tenant middleware, multi-tenant deployments routing
// per-domain admin panels) that disagrees with the :id path parameter.
// Fail-open when unresolved (single-tenant deployments, or the tenant store
// isn't wired) — mirrors domains/tenant.ClientOK and the identical guard in
// interfaces/sso's resolveHomeRealm: only rejects when BOTH sides are known
// and actually disagree, never on absence of tenant context.
func tenantRequestMismatch(ctx core.HandlerContext, tenantID string) bool {
	r, ok := tenant.FromHandlerContext(ctx)
	return ok && r != nil && r.Tenant != nil && r.Tenant.ID != "" && r.Tenant.ID != tenantID
}

// recordAdminTenantExport emits admin_tenant_exported with the manifest's
// section counts as metadata (bounded — fixed keys, small integer values,
// never per-request/PII data) so the audit trail shows what was exported
// without duplicating the bundle's contents into the log.
func recordAdminTenantExport(d Deps, ctx core.HandlerContext, tenantID string, opErr error) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	evt := &audit.Event{
		Type:      audit.EventAdminTenantExported,
		Outcome:   audit.OutcomeSuccess,
		ActorID:   actor,
		ActorIP:   audit.ClientIP(ctx.Request()),
		Timestamp: time.Now().UTC(),
	}
	audit.SetMeta(evt, core.KeyTenantID, tenantID)
	if opErr != nil {
		evt.Outcome = audit.OutcomeFailure
		evt.Reason = opErr.Error()
	}
	aud.Record(ctx.Request().Context(), evt)
}

// Zero-trust conditional-access (CAP) policy governance view. Read-only: policy
// authoring is out of band (a YAML bundle loaded at boot / a later admin
// mutation surface), so this handler only lists. Gated by AdminMiddleware
// (admin:read via the /api/v1/admin/ prefix). Relocated from
// accesspolicies.go to keep interfaces/admin within its per-directory
// go-file fan-out budget.

// HandleAdminListAccessPolicies serves GET /api/v1/admin/access-policies — the
// wired conditional-access policies ordered by evaluation precedence (priority
// desc, then name), so an operator sees the order the engine resolves them in.
// admin:read.
func HandleAdminListAccessPolicies(d Deps, ctx core.HandlerContext) {
	store := d.ConditionalAccessStore()
	if store == nil {
		// Defensive: the route is only mounted when the engine is wired, but
		// guard so a future refactor can't reach a nil store.
		ctx.JSON(http.StatusOK, map[string]any{"policies": []conditionalaccess.Policy{}, "total": 0})
		return
	}
	policies, err := store.List(ctx.Request().Context())
	if err != nil {
		d.Logger().Error("admin list access policies failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	sortAccessPoliciesByPrecedence(policies)
	ctx.JSON(http.StatusOK, map[string]any{"policies": policies, "total": len(policies)})
}

// sortAccessPoliciesByPrecedence orders the governance view the way the engine
// evaluates: higher priority first, then name for a stable, deterministic view.
// (The engine additionally breaks ties on condition specificity; the view keeps
// to the two operator-visible keys.)
func sortAccessPoliciesByPrecedence(policies []conditionalaccess.Policy) {
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority > policies[j].Priority
		}
		return policies[i].Name < policies[j].Name
	})
}

// Enterprise-connection email-domain ownership verification (DNS-TXT
// challenge), relocated from connection_domains.go to keep interfaces/admin
// within its per-directory go-file fan-out budget. A domain routes to at
// most one connection; when verification is enabled on the store, a
// competing connection cannot steal a VERIFIED domain's home-realm routing
// without proving DNS control through the verify endpoint here.

// domainClaimJSON is the wire shape for one (connection, domain) claim.
//
// Token is intentionally returned in this admin listing: a DNS-TXT challenge
// token is published in public DNS by design (the proof is control of the DNS
// zone, ACME dns-01 style), so it is not a bearer secret and the admin needs it
// to create the TXT record. It is never logged.
type domainClaimJSON struct {
	Domain     string `json:"domain"`
	Status     string `json:"status"`
	Record     string `json:"record"`
	Token      string `json:"token"`
	CreatedAt  string `json:"created_at,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
}

func domainClaimToJSON(c *connections.DomainVerification) domainClaimJSON {
	j := domainClaimJSON{Domain: c.Domain, Status: string(c.Status), Record: c.Record, Token: c.Token}
	if !c.CreatedAt.IsZero() {
		j.CreatedAt = c.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !c.VerifiedAt.IsZero() {
		j.VerifiedAt = c.VerifiedAt.UTC().Format(time.RFC3339)
	}
	return j
}

// HandleAdminListConnectionDomains serves GET
// /api/v1/admin/connections/:id/domains — the connection's OWN email-domain
// claims (pending + verified) with the DNS TXT record to publish. admin:read.
// 404 when the connection does not exist. Returns only this connection's claims
// (no cross-connection lookup).
func HandleAdminListConnectionDomains(d Deps, ctx core.HandlerContext) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.ConnectionStore()
	if _, err := store.Get(ctx.Request().Context(), id); err != nil {
		if errors.Is(err, connections.ErrNoConnection) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin list connection domains: get failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	claims, err := store.DomainClaims(ctx.Request().Context(), id)
	if err != nil {
		d.Logger().Error("admin list connection domains failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	out := make([]domainClaimJSON, 0, len(claims))
	for _, c := range claims {
		out = append(out, domainClaimToJSON(c))
	}
	ctx.JSON(http.StatusOK, map[string]any{"domains": out})
}

// HandleAdminVerifyConnectionDomain serves POST
// /api/v1/admin/connections/:id/domains/:domain/verify — a synchronous DNS-TXT
// ownership check. admin:write. Returns 200 in BOTH outcomes (not-yet-verified
// is a state, not an error — mirrors /introspect's {"active":false}); 404 only
// when the connection has not claimed the domain. On a successful verification
// it invalidates the connection cache and audits the event.
func HandleAdminVerifyConnectionDomain(d Deps, ctx core.HandlerContext) {
	id, domain := ctx.Param("id"), ctx.Param("domain")
	if id == "" || domain == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.ConnectionStore()
	verified, err := connections.VerifyDomainOwnership(ctx.Request().Context(), store, d.DomainResolver(), id, domain, 0)
	if errors.Is(err, connections.ErrNoDomainClaim) {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	if err != nil {
		// Fail-closed: a store/lookup error is never reported as verified.
		d.Logger().Error("admin verify connection domain failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	claim, err := store.DomainClaim(ctx.Request().Context(), id, domain)
	if err != nil {
		d.Logger().Error("admin verify connection domain: reload failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if verified {
		d.InvalidateConnectionCache(id)
		recordConnectionDomainVerified(d, ctx, store, id)
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"verified": verified, "status": string(claim.Status),
		"record": claim.Record, "token": claim.Token,
	})
}

// recordConnectionDomainVerified emits the audit event with the owning tenant.
func recordConnectionDomainVerified(d Deps, ctx core.HandlerContext, store connections.Store, id string) {
	tenantID := ""
	if conn, err := store.Get(ctx.Request().Context(), id); err == nil {
		tenantID = conn.TenantID
	}
	recordAdminConnectionAction(d, ctx, audit.EventAdminConnectionDomainVerified, id, tenantID)
}
