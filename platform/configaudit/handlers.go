package configaudit

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Query parameter names for GET /api/v1/admin/config/history.
const (
	QueryResource = "resource"
	QuerySince    = "since"
	QueryLimit    = "limit"
	// QueryApprove is the mandatory explicit-approval flag for the
	// apply/rollback write endpoints: ?approve=true or the write is refused
	// before any state is touched (misoperation barrier, see
	// docs/design/config-apply-mode.md Decision 1).
	QueryApprove = "approve"
)

// Response body keys for the config-audit admin endpoints.
const (
	KeyRunning     = "running"
	KeyApplied     = "applied"
	KeyPatch       = "patch"
	KeyEntries     = "entries"
	KeyCount       = "count"
	KeyVersion     = "version"
	KeyPrevVersion = "prev_version"
)

// ErrNotAvailable is the wire error code returned (HTTP 501) when a
// config-audit endpoint is hit but its backing wiring (WithConfigSnapshots
// / WithConfigAuditStore) was never configured — distinguishes "this
// deployment doesn't use the feature" from a real 500.
const ErrNotAvailable = "config_audit_not_available"

// HandlerDeps is what the config-audit HTTP handlers need. *sso.Server
// satisfies it via its accessor methods (interfaces/sso/accessors.go),
// exactly like platform/audit.HandlerDeps. Auditor / ActorFromContext feed
// the apply/rollback audit trail (the admin actor stamped by the admin
// middleware, resolved through the Server's own accessor so this platform
// package never imports interfaces).
type HandlerDeps interface {
	ConfigAuditStore() Store
	AppliedConfigSnapshot() (map[string]any, error)
	RunningConfigSnapshot(ctx context.Context) (map[string]any, error)
	SrvLogger() spi.Logger
	Auditor() *audit.Recorder
	ActorFromContext(ctx context.Context) (userID, clientID string, ok bool)
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

// ClusterDiffRequest is the POST body for HandleClusterDiff: a PEER
// cluster's config snapshot to diff against this cluster's own running
// config. Typically populated verbatim from that peer's own
// GET .../config/running response body's "running" field — this endpoint
// never fetches a peer itself, so wiring it adds no new outbound network
// capability or peer-discovery mechanism, only a diff computation.
type ClusterDiffRequest struct {
	Snapshot map[string]any `json:"snapshot"`
}

// HandleClusterDiff implements POST /api/v1/admin/config/cluster-diff: an
// RFC 6902 JSON Patch turning a caller-supplied PEER cluster's config
// snapshot into THIS cluster's own running config, redacted. This is the
// cross-cluster counterpart of HandleDiff (which only ever compares THIS
// replica's own applied vs. running snapshots) — an operator (or a small
// external reconciler) fetches two clusters' GET .../config/running
// bodies and feeds one into the other's HandleClusterDiff to see what
// would need to change to reconcile them, reusing the exact same
// Diff/RedactOps pipeline rather than a new comparison mechanism.
func HandleClusterDiff(d HandlerDeps, ctx core.HandlerContext) {
	var req ClusterDiffRequest
	if err := ctx.Bind(&req); err != nil || len(req.Snapshot) == 0 {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest})
		return
	}
	running, err := d.RunningConfigSnapshot(ctx.Request().Context())
	if err != nil {
		writeSnapshotError(d, ctx, "running config snapshot", err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyPatch: RedactOps(Diff(req.Snapshot, running))})
}

// ApplyRequest is the POST body for HandleApply: a PEER cluster's config
// snapshot (typically the "running" field of that peer's own
// GET .../config/running response) plus the peer config's canonical digest
// (configaudit.Digest — the drift loop's fingerprint, see Decision 4 of
// docs/design/config-apply-mode.md) and a mandatory operator reason.
type ApplyRequest struct {
	Snapshot map[string]any `json:"snapshot"`
	Digest   string         `json:"digest"`
	Reason   string         `json:"reason"`
}

// RollbackRequest is the POST body for HandleRollback: the mandatory
// operator reason (an unexplained governance reversal is itself an audit
// finding, mirroring break-glass / change-approval).
type RollbackRequest struct {
	Reason string `json:"reason"`
}

// HandleApply implements POST /api/v1/admin/config/apply?approve=true: it
// records the caller-supplied PEER config snapshot as this cluster's new
// applied-config baseline (admin:write — the default HTTP scope for a
// non-GET admin path, so NO SetMethodScope override exists for this route,
// the exact opposite of cluster-diff's read downgrade). The write is gated
// by (a) ?approve=true — a missing/false flag is a hard 400 before any
// state is touched — and (b) the split-brain digest check: the server
// recomputes configaudit.Digest(snapshot) over the RAW snapshot and
// compares it byte-wise to the required digest field; a mismatch is a 409
// (stale or mixed-source submission, nothing recorded). Only the REDACTED
// snapshot is ever stored; the audit event carries metadata only
// (apply_id, peer_digest, prev_id, actor, IP) — never snapshot content.
func HandleApply(d HandlerDeps, ctx core.HandlerContext) {
	if !approved(ctx) {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrConfigApplyApprovalRequired})
		return
	}
	store := d.ConfigAuditStore()
	if store == nil {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: ErrNotAvailable})
		return
	}
	var req ApplyRequest
	if err := ctx.Bind(&req); err != nil || len(req.Snapshot) == 0 {
		ctx.JSON(http.StatusBadRequest, map[string]string{
			core.KeyError: core.ErrInvalidRequest, core.KeyErrorDescription: "snapshot is required",
		})
		return
	}
	digest := strings.TrimSpace(req.Digest)
	reason := strings.TrimSpace(req.Reason)
	if digest == "" || reason == "" {
		ctx.JSON(http.StatusBadRequest, map[string]string{
			core.KeyError: core.ErrInvalidRequest, core.KeyErrorDescription: "digest and reason are required",
		})
		return
	}
	got, err := Digest(req.Snapshot)
	if err != nil {
		d.SrvLogger().Error("config audit: apply digest failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	if got != digest {
		ctx.JSON(http.StatusConflict, map[string]string{core.KeyError: core.ErrConfigApplyConflict})
		return
	}
	actor, _, _ := d.ActorFromContext(ctx.Request().Context())
	v, err := store.Apply(ctx.Request().Context(), AppliedVersion{
		Actor: actor, Digest: got, Reason: reason, Snapshot: Redact(req.Snapshot),
	})
	if err != nil {
		d.SrvLogger().Error("config audit: apply failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	recordConfigApplyAudit(d, ctx, v, audit.EventAdminConfigApplied)
	writeApplyResponse(d, ctx, v)
}

// HandleRollback implements POST /api/v1/admin/config/rollback?approve=true:
// it re-declares the PREVIOUS applied-config baseline as the new latest (a
// new append-only version, see Store.Rollback), so the applied view and
// subsequent diffs revert to that snapshot. Same gates as apply: mandatory
// ?approve=true and mandatory reason. 409 config_apply_no_previous when
// there is no baseline or no predecessor to restore.
func HandleRollback(d HandlerDeps, ctx core.HandlerContext) {
	if !approved(ctx) {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrConfigApplyApprovalRequired})
		return
	}
	store := d.ConfigAuditStore()
	if store == nil {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: ErrNotAvailable})
		return
	}
	var req RollbackRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{
			core.KeyError: core.ErrInvalidRequest, core.KeyErrorDescription: "reason is required",
		})
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		ctx.JSON(http.StatusBadRequest, map[string]string{
			core.KeyError: core.ErrInvalidRequest, core.KeyErrorDescription: "reason is required",
		})
		return
	}
	actor, _, _ := d.ActorFromContext(ctx.Request().Context())
	v, err := store.Rollback(ctx.Request().Context(), actor, reason)
	if errors.Is(err, ErrNoAppliedVersion) {
		ctx.JSON(http.StatusConflict, map[string]string{core.KeyError: core.ErrConfigApplyNoPrevious})
		return
	}
	if err != nil {
		d.SrvLogger().Error("config audit: rollback failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	recordConfigApplyAudit(d, ctx, v, audit.EventAdminConfigRolledBack)
	writeApplyResponse(d, ctx, v)
}

// approved reports whether the mandatory explicit-approval flag was set
// (?approve=true). Every apply/rollback write requires it.
func approved(ctx core.HandlerContext) bool {
	return ctx.Query(QueryApprove) == "true"
}

// writeApplyResponse emits the apply/rollback success body: the redacted
// applied snapshot, the new version id, its predecessor, and the redacted
// patch from the new baseline to this cluster's running config (informational
// only — best-effort: when the running snapshot fails, the patch is omitted
// and the failure is logged, mirroring the observability fail-open posture).
func writeApplyResponse(d HandlerDeps, ctx core.HandlerContext, v AppliedVersion) {
	body := map[string]any{
		KeyApplied:     v.Snapshot,
		KeyVersion:     v.ID,
		KeyPrevVersion: v.PrevID,
	}
	running, err := d.RunningConfigSnapshot(ctx.Request().Context())
	if err != nil {
		d.SrvLogger().Error("config audit: apply response diff failed", "error", err)
	} else {
		body[KeyPatch] = RedactOps(Diff(v.Snapshot, running))
	}
	ctx.JSON(http.StatusOK, body)
}

// recordConfigApplyAudit emits the apply/rollback audit event with the
// evidence chain: apply_id (the new version id), peer_digest, and prev_id.
// Metadata only — never snapshot content. No-op when no Auditor is wired
// (audit stays fail-open, matching drift.go).
func recordConfigApplyAudit(d HandlerDeps, ctx core.HandlerContext, v AppliedVersion, evtType audit.EventType) {
	rec := d.Auditor()
	if rec == nil {
		return
	}
	actor, _, _ := d.ActorFromContext(ctx.Request().Context())
	evt := &audit.Event{Type: evtType, Outcome: audit.OutcomeSuccess, ActorID: actor, ActorIP: audit.ClientIP(ctx.Request())}
	audit.SetMeta(evt, "apply_id", v.ID)
	audit.SetMeta(evt, "peer_digest", v.Digest)
	if v.PrevID != "" {
		audit.SetMeta(evt, "prev_id", v.PrevID)
	}
	rec.Record(ctx.Request().Context(), evt)
}
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
