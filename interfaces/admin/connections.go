package admin

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/snaplink/sso/domains/conditionalaccess"
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
