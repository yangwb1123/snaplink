package admin

import (
	"errors"
	"net/http"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// B2B enterprise-connection admin CRUD, extracted from package sso (root) into
// the admin domain. *sso.Server keeps thin wrappers delegating here.
// Behavior-identical to the prior inline definitions; gated by AdminMiddleware.

// connectionJSON is the wire shape for admin enterprise-connection management.
type connectionJSON struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Type        string            `json:"type"`
	DisplayName string            `json:"display_name"`
	Domains     []string          `json:"domains"`
	Enabled     bool              `json:"enabled"`
	Config      map[string]string `json:"config,omitempty"`
}

func connectionToJSON(c *connections.Connection) connectionJSON {
	return connectionJSON{
		ID: c.ID, TenantID: c.TenantID, Type: string(c.Type),
		DisplayName: c.DisplayName, Domains: c.Domains, Enabled: c.Enabled, Config: c.Config,
	}
}

// recordAdminConnectionAction emits a connection-mutation audit event keyed on
// the acting admin, with connection_id + tenant_id metadata.
func recordAdminConnectionAction(d Deps, ctx core.HandlerContext, evtType audit.EventType, connID, tenantID string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	evt := &audit.Event{Type: evtType, Outcome: audit.OutcomeSuccess, ActorID: actor, ActorIP: audit.ClientIP(ctx.Request())}
	audit.SetMeta(evt, "connection_id", connID)
	audit.SetMeta(evt, core.KeyTenantID, tenantID)
	aud.Record(ctx.Request().Context(), evt)
}

// HandleAdminListConnections serves GET /api/v1/admin/connections?tenant_id=
// — lists a tenant's B2B enterprise connections. admin:read. tenant_id is
// required (the store indexes by tenant; there is no cross-tenant list).
func HandleAdminListConnections(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Request().URL.Query().Get(core.KeyTenantID)
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	conns, err := d.ConnectionStore().ByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		d.Logger().Error("admin list connections failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	out := make([]connectionJSON, 0, len(conns))
	for _, c := range conns {
		out = append(out, connectionToJSON(c))
	}
	ctx.JSON(http.StatusOK, map[string]any{"connections": out})
}

// HandleAdminGetConnection serves GET /api/v1/admin/connections/:id. admin:read.
// A missing connection is a 404.
func HandleAdminGetConnection(d Deps, ctx core.HandlerContext) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	c, err := d.ConnectionStore().Get(ctx.Request().Context(), id)
	if err != nil {
		if errors.Is(err, connections.ErrNoConnection) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin get connection failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, connectionToJSON(c))
}

// HandleAdminUpsertConnection serves POST /api/v1/admin/connections — create or
// replace a connection (and its domain routing). admin:write. Requires id +
// tenant_id; type must be oidc or saml. Emits admin_connection_upserted.
func HandleAdminUpsertConnection(d Deps, ctx core.HandlerContext) {
	var req connectionJSON
	if err := oauth.BindParams(ctx, &req); err != nil || req.ID == "" || req.TenantID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	ct := connections.ConnectionType(req.Type)
	if ct != connections.TypeOIDC && ct != connections.TypeSAML {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	conn := &connections.Connection{
		ID: req.ID, TenantID: req.TenantID, Type: ct,
		DisplayName: req.DisplayName, Domains: req.Domains, Enabled: req.Enabled, Config: req.Config,
	}
	if err := d.ConnectionStore().Upsert(ctx.Request().Context(), conn); err != nil {
		d.Logger().Error("admin upsert connection failed", "id", req.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminConnectionAction(d, ctx, audit.EventAdminConnectionUpserted, req.ID, req.TenantID)
	ctx.JSON(http.StatusOK, connectionToJSON(conn))
}

// HandleAdminDeleteConnection serves DELETE /api/v1/admin/connections/:id.
// admin:write. Idempotent (the store contract makes Delete a no-op on a missing
// id). Emits admin_connection_deleted.
func HandleAdminDeleteConnection(d Deps, ctx core.HandlerContext) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := d.ConnectionStore().Delete(ctx.Request().Context(), id); err != nil {
		d.Logger().Error("admin delete connection failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminConnectionAction(d, ctx, audit.EventAdminConnectionDeleted, id, "")
	ctx.JSON(http.StatusNoContent, nil)
}
