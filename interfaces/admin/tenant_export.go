package admin

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/shared/core"
)

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
