package configaudit

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// Query parameter names for GET /api/v1/admin/config/history.
const (
	QueryResource = "resource"
	QuerySince    = "since"
	QueryLimit    = "limit"
)

// Response body keys for the config-audit admin endpoints.
const (
	KeyRunning = "running"
	KeyApplied = "applied"
	KeyPatch   = "patch"
	KeyEntries = "entries"
	KeyCount   = "count"
)

// ErrNotAvailable is the wire error code returned (HTTP 501) when a
// config-audit endpoint is hit but its backing wiring (WithConfigSnapshots
// / WithConfigAuditStore) was never configured — distinguishes "this
// deployment doesn't use the feature" from a real 500.
const ErrNotAvailable = "config_audit_not_available"

// HandlerDeps is what the config-audit HTTP handlers need. *sso.Server
// satisfies it via its accessor methods (interfaces/sso/accessors.go),
// exactly like platform/audit.HandlerDeps.
type HandlerDeps interface {
	ConfigAuditStore() Store
	AppliedConfigSnapshot() (map[string]any, error)
	RunningConfigSnapshot(ctx context.Context) (map[string]any, error)
	SrvLogger() spi.Logger
}

// HandleRunning implements GET /api/v1/admin/config/running: the CURRENT
// effective config snapshot, redacted.
func HandleRunning(d HandlerDeps, ctx core.HandlerContext) {
	running, err := d.RunningConfigSnapshot(ctx.Request().Context())
	if err != nil {
		writeSnapshotError(d, ctx, "running config snapshot", err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyRunning: Redact(running)})
}

// HandleApplied implements GET /api/v1/admin/config/applied: the config
// snapshot captured once at server startup, redacted.
func HandleApplied(d HandlerDeps, ctx core.HandlerContext) {
	applied, err := d.AppliedConfigSnapshot()
	if err != nil {
		writeSnapshotError(d, ctx, "applied config snapshot", err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyApplied: Redact(applied)})
}

// HandleDiff implements GET /api/v1/admin/config/diff: an RFC 6902 JSON
// Patch turning the applied config into the running config, redacted.
func HandleDiff(d HandlerDeps, ctx core.HandlerContext) {
	applied, err := d.AppliedConfigSnapshot()
	if err != nil {
		writeSnapshotError(d, ctx, "applied config snapshot", err)
		return
	}
	running, err := d.RunningConfigSnapshot(ctx.Request().Context())
	if err != nil {
		writeSnapshotError(d, ctx, "running config snapshot", err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyPatch: RedactOps(Diff(applied, running))})
}

// HandleHistory implements GET /api/v1/admin/config/history, optionally
// filtered by ?resource=&since=&limit=.
func HandleHistory(d HandlerDeps, ctx core.HandlerContext) {
	store := d.ConfigAuditStore()
	if store == nil {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: ErrNotAvailable})
		return
	}
	f, err := parseHistoryFilter(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest, core.KeyErrorDescription: err.Error()})
		return
	}
	entries, err := store.List(ctx.Request().Context(), f)
	if err != nil {
		d.SrvLogger().Error("config history query failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyEntries: entries, KeyCount: len(entries)})
}

// writeSnapshotError distinguishes "feature not wired" (ErrSnapshotUnavailable
// -> 501) from a genuine read failure (-> 500, logged).
func writeSnapshotError(d HandlerDeps, ctx core.HandlerContext, what string, err error) {
	if errors.Is(err, ErrSnapshotUnavailable) {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: ErrNotAvailable})
		return
	}
	d.SrvLogger().Error("config audit: "+what+" failed", "error", err)
	ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
}

// parseHistoryFilter reads the history query-string filter, mirroring
// platform/audit's parseQuery/parseTime conventions (RFC3339 timestamps).
func parseHistoryFilter(ctx core.HandlerContext) (Filter, error) {
	f := Filter{Resource: ctx.Query(QueryResource)}
	if v := ctx.Query(QuerySince); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, err
		}
		f.Since = t
	}
	if v := ctx.Query(QueryLimit); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return f, err
		}
		f.Limit = n
	}
	return f, nil
}
