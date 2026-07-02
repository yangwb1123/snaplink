package admin

import (
	"errors"
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

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
