package admin

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/connections/provider"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
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
	d.InvalidateConnectionCache(req.ID)
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
	d.InvalidateConnectionCache(id)
	recordAdminConnectionAction(d, ctx, audit.EventAdminConnectionDeleted, id, "")
	ctx.JSON(http.StatusNoContent, nil)
}

// Enterprise-connection health telemetry: a stored last-probe-outcome record
// (status/last-success/last-error) plus an admin-triggered synchronous probe
// that actually attempts the OIDC discovery / SAML metadata fetch and
// updates it. Mirrors the domain-verification handlers' shape (a GET reader +
// a POST that performs the real check and persists the result).

// connectionHealthJSON is the wire shape for both the GET .../health reader
// and the POST .../probe response (the probe returns the record it just wrote).
type connectionHealthJSON struct {
	ConnectionID  string `json:"connection_id"`
	Status        string `json:"status"`
	LastCheckedAt string `json:"last_checked_at,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

func connectionHealthToJSON(h *connections.ConnectionHealth) connectionHealthJSON {
	j := connectionHealthJSON{ConnectionID: h.ConnectionID, Status: string(h.Status), LastError: h.LastError}
	if !h.LastCheckedAt.IsZero() {
		j.LastCheckedAt = h.LastCheckedAt.UTC().Format(time.RFC3339)
	}
	if !h.LastSuccessAt.IsZero() {
		j.LastSuccessAt = h.LastSuccessAt.UTC().Format(time.RFC3339)
	}
	return j
}

// HandleAdminGetConnectionHealth serves GET
// /api/v1/admin/connections/:id/health — the LAST recorded probe outcome
// (admin:read). 404 when the connection doesn't exist. Never triggers a
// fresh probe itself (that's POST .../probe); an unprobed connection reads
// back status=unknown.
func HandleAdminGetConnectionHealth(d Deps, ctx core.HandlerContext) {
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
		d.Logger().Error("admin get connection health: get failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	h, err := store.Health(ctx.Request().Context(), id)
	if err != nil {
		d.Logger().Error("admin get connection health failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, connectionHealthToJSON(h))
}

// HandleAdminProbeConnection serves POST
// /api/v1/admin/connections/:id/probe — synchronously attempts a lightweight
// reachability/handshake check against the connection's configured upstream
// (OIDC discovery fetch, or SAML metadata fetch, per Connection.Type) and
// persists the outcome. admin:write. 404 when the connection doesn't exist.
// Always 200 with the recorded health, even on a degraded/unreachable
// outcome — the CHECK itself succeeded; the result may be bad news (mirrors
// the domain-verify endpoint's "not yet verified is a state, not an error"
// contract). Emits admin_connection_probed and records
// sso_connection_health_probes_total{type,outcome} (bounded cardinality).
func HandleAdminProbeConnection(d Deps, ctx core.HandlerContext) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.ConnectionStore()
	conn, err := store.Get(ctx.Request().Context(), id)
	if err != nil {
		if errors.Is(err, connections.ErrNoConnection) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin probe connection: get failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	h, err := connections.RunProbe(ctx.Request().Context(), store, d.ConnectionProber(), conn)
	if err != nil {
		d.Logger().Error("admin probe connection failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	observeConnectionProbe(d, conn, h.Status)
	recordAdminConnectionProbe(d, ctx, conn, h)
	ctx.JSON(http.StatusOK, connectionHealthToJSON(h))
}

// observeConnectionProbe increments the bounded-cardinality probe counter.
// Nil-safe: a no-op when metrics aren't wired.
func observeConnectionProbe(d Deps, conn *connections.Connection, status connections.HealthStatus) {
	m := d.Metrics()
	if m == nil {
		return
	}
	m.ConnectionHealthProbesTotal.WithLabelValues(string(conn.Type), string(status)).Inc()
}

// recordAdminConnectionProbe emits the audit event, carrying the outcome
// status so the SOC2/SIEM trail records not just "a probe ran" but "what it
// found" without growing the event-type vocabulary per health state.
func recordAdminConnectionProbe(d Deps, ctx core.HandlerContext, conn *connections.Connection, h *connections.ConnectionHealth) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	evt := &audit.Event{Type: audit.EventAdminConnectionProbed, Outcome: audit.OutcomeSuccess, ActorID: actor, ActorIP: audit.ClientIP(ctx.Request())}
	audit.SetMeta(evt, "connection_id", conn.ID)
	audit.SetMeta(evt, core.KeyTenantID, conn.TenantID)
	audit.SetMeta(evt, "health_status", string(h.Status))
	aud.Record(ctx.Request().Context(), evt)
}

// ============================================================================
// Third-party login provider admin CRUD
// ============================================================================

type providerJSON struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id,omitempty"`
	Type        string            `json:"type"`
	DisplayName string            `json:"display_name"`
	IconURL     string            `json:"icon_url,omitempty"`
	ButtonLabel string            `json:"button_label,omitempty"`
	ButtonColor string            `json:"button_color,omitempty"`
	Enabled     bool              `json:"enabled"`
	Config      map[string]string `json:"config,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
}

func providerToJSON(p *provider.Provider) providerJSON {
	return providerJSON{
		ID: p.ID, TenantID: p.TenantID, Type: string(p.Type),
		DisplayName: p.DisplayName, IconURL: p.IconURL,
		ButtonLabel: p.ButtonLabel, ButtonColor: p.ButtonColor,
		Enabled: p.Enabled, Config: p.Config,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

func providerFromJSON(j providerJSON) *provider.Provider {
	return &provider.Provider{
		ID: j.ID, TenantID: j.TenantID, Type: provider.ProviderType(j.Type),
		DisplayName: j.DisplayName, IconURL: j.IconURL,
		ButtonLabel: j.ButtonLabel, ButtonColor: j.ButtonColor,
		Enabled: j.Enabled, Config: j.Config,
	}
}

func recordAdminProviderAction(d Deps, ctx core.HandlerContext, evtType audit.EventType, providerID, tenantID string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	evt := &audit.Event{Type: evtType, Outcome: audit.OutcomeSuccess, ActorID: actor, ActorIP: audit.ClientIP(ctx.Request())}
	audit.SetMeta(evt, "provider_id", providerID)
	audit.SetMeta(evt, core.KeyTenantID, tenantID)
	aud.Record(ctx.Request().Context(), evt)
}

func HandleAdminListProviders(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	tenantID := ctx.Request().URL.Query().Get(core.KeyTenantID)
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	list, err := store.ListByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		d.Logger().Error("admin: list providers", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].DisplayName < list[j].DisplayName })
	out := make([]providerJSON, len(list))
	for i, p := range list {
		out[i] = providerToJSON(p)
	}
	ctx.JSON(http.StatusOK, map[string]any{"providers": out})
}

func HandleAdminGetProvider(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	p, err := store.Get(ctx.Request().Context(), id)
	if err != nil {
		if errors.Is(err, provider.ErrNoSuchProvider) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin: get provider", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, providerToJSON(p))
}

func HandleAdminCreateProvider(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	var j providerJSON
	if err := ctx.Bind(&j); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(core.ErrInvalidRequest, err.Error()))
		return
	}
	if j.ID == "" || j.Type == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if j.Config == nil {
		j.Config = make(map[string]string)
	}
	p := providerFromJSON(j)
	if err := store.Create(ctx.Request().Context(), p); err != nil {
		if errors.Is(err, provider.ErrProviderExists) {
			ctx.JSON(http.StatusConflict, core.ErrorBody("provider_already_exists"))
			return
		}
		d.Logger().Error("admin: create provider", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminProviderAction(d, ctx, audit.EventType("provider_created"), p.ID, p.TenantID)
	ctx.JSON(http.StatusCreated, providerToJSON(p))
}

func HandleAdminUpdateProvider(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var j providerJSON
	if err := ctx.Bind(&j); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(core.ErrInvalidRequest, err.Error()))
		return
	}
	j.ID = id
	p := providerFromJSON(j)
	if err := store.Update(ctx.Request().Context(), p); err != nil {
		if errors.Is(err, provider.ErrNoSuchProvider) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin: update provider", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminProviderAction(d, ctx, audit.EventType("provider_updated"), p.ID, p.TenantID)
	ctx.JSON(http.StatusOK, providerToJSON(p))
}

func HandleAdminDeleteProvider(d Deps, ctx core.HandlerContext) {
	store := d.ProviderStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	p, err := store.Get(ctx.Request().Context(), id)
	if err != nil && !errors.Is(err, provider.ErrNoSuchProvider) {
		d.Logger().Error("admin: get provider before delete", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	tenantID := ""
	if p != nil {
		tenantID = p.TenantID
	}
	if err := store.Delete(ctx.Request().Context(), id); err != nil {
		d.Logger().Error("admin: delete provider", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminProviderAction(d, ctx, audit.EventType("provider_deleted"), id, tenantID)
	ctx.JSON(http.StatusOK, map[string]any{core.KeyStatus: core.StatusOK})
}
