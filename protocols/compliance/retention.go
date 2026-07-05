package compliance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// auditRetentionReportCap bounds the audit-retention report-only query so a
// periodic background sweep never pages an entire (potentially unbounded)
// audit history — the count is a "found at least this many" signal, not an
// exact total, once it hits the cap. An operator needing an exact figure
// uses GET /api/v1/audit/events directly (platform/audit's own Query API).
const auditRetentionReportCap = audit.MaxQueryLimit

// RetentionConfig gates the automated data-retention sweep. The zero value is
// OFF: with Enabled false, Sweep is a no-op, so a build that never sets this
// behaves identically to one without the feature.
type RetentionConfig struct {
	// Enabled turns the whole sweep on. False (the default) makes Sweep a
	// no-op regardless of the other fields.
	Enabled bool

	// SessionTTLSweep destroys sessions whose ExpiresAt has passed — a
	// storage-hygiene reclaim (an expired session is already refused on
	// read; this just removes the now-useless record). Requires
	// SessionManager.ListAll, which a backend MAY refuse
	// (core.ErrUnsupportedOperation) — reported as Skipped, not an error.
	SessionTTLSweep bool

	// DormantAfter flags accounts whose most recent SessionManager record
	// (across every session ever created for them, per ListAll — NOT
	// ListByUser, which filters out already-expired sessions and would make
	// a truly-dormant account's history invisible) is older than this window
	// as erasure-review candidates — the "dormant erasure-eligible accounts"
	// step. An account with NO session history at all is left alone (absence
	// of evidence is not evidence of dormancy — e.g. an API/service account
	// that only ever uses client_credentials). 0 disables this step.
	DormantAfter time.Duration

	// AutoEraseDormant, when true AND Eraser is wired, actually erases a
	// flagged dormant account (via Eraser.EraseSubject) instead of only
	// flagging it in RetentionReport.DormantAccountsFlagged. False (the
	// default) is report-only — session recency is a heuristic, not a
	// definitive signal an account is safe to destroy, so automatic erasure
	// is a deliberate, separate opt-in on top of DormantAfter.
	AutoEraseDormant bool

	// AuditReportMaxAge, when > 0, REPORTS (never deletes — see
	// auditRetentionReportCap doc) a count of audit events older than
	// now-AuditReportMaxAge. Deletion of audit history has its own
	// dedicated, backend-specific mechanism (e.g. a SQL sink's own prune
	// routine); this sweep only surfaces the count so an operator without
	// that wiring (e.g. an in-memory-sink deployment) still gets visibility.
	AuditReportMaxAge time.Duration

	// DryRun previews every destructive step without mutating anything —
	// mirrors EraseOptions.DryRun. The audit-retention step is unaffected (it
	// never mutates regardless of DryRun).
	DryRun bool

	// MaxPerSweep caps destructive actions PER STEP per sweep (a storm guard,
	// mirroring the bulk-revoke caps elsewhere in this codebase). 0 = unlimited.
	MaxPerSweep int
}

// RetentionSweeper runs the configured retention steps against whatever
// stores are wired — composing EXISTING primitives (SessionManager.ListAll /
// ListByUser / Destroy, Eraser, audit.Recorder.Sink().Query) rather than
// adding new tracking. A nil field simply skips its step
// (RetentionReport.Skipped notes why), so an operator can enable a subset
// (e.g. session cleanup only) by wiring only that field.
type RetentionSweeper struct {
	Users    core.UserProvider
	Sessions core.SessionManager
	// Eraser performs the dormant-account auto-erase step (only when
	// RetentionConfig.AutoEraseDormant is set). Deliberately reused rather
	// than requiring a second wiring option: Eraser.EraseSubject already
	// accepts any subject id, not just a caller's own account, so the SAME
	// instance wired for self-service erasure (WithSelfServiceAccountErasure)
	// works here unchanged.
	Eraser *Eraser
	// Auditor backs the audit-retention REPORT step (via Auditor.Sink().Query).
	Auditor *audit.Recorder
	Logger  spi.Logger
	// Now overrides the clock for tests. Nil ⇒ time.Now().UTC().
	Now func() time.Time
}

func (s *RetentionSweeper) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// RetentionReport is the outcome of one sweep pass, JSON-marshalable as-is.
type RetentionReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	DryRun      bool      `json:"dry_run"`

	SessionsExpiredFound int `json:"sessions_expired_found"`
	SessionsDestroyed    int `json:"sessions_destroyed"`

	// DormantAccountsFlagged lists the user IDs whose last known session
	// activity is older than RetentionConfig.DormantAfter (review candidates).
	DormantAccountsFlagged []string `json:"dormant_accounts_flagged,omitempty"`
	DormantAccountsErased  int      `json:"dormant_accounts_erased"`

	// AuditEventsPastRetention is a COUNT ONLY (bounded by
	// auditRetentionReportCap) — see RetentionConfig.AuditReportMaxAge doc.
	AuditEventsPastRetention int `json:"audit_events_past_retention"`

	Skipped []string `json:"skipped,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

// Sweep runs one pass of every enabled step. A zero RetentionReport (no
// error) when cfg.Enabled is false — the byte-identical-when-off contract.
// Best-effort per step: a failing step is recorded in Errors and never
// aborts the others (same convention as Eraser.EraseSubject).
func (s *RetentionSweeper) Sweep(ctx context.Context, cfg RetentionConfig) (*RetentionReport, error) {
	rep := &RetentionReport{GeneratedAt: s.now(), DryRun: cfg.DryRun}
	if !cfg.Enabled {
		return rep, nil
	}
	if cfg.SessionTTLSweep {
		s.sweepSessions(ctx, cfg, rep)
	}
	if cfg.DormantAfter > 0 {
		s.sweepDormantAccounts(ctx, cfg, rep)
	}
	if cfg.AuditReportMaxAge > 0 {
		s.reportAuditRetention(ctx, cfg, rep)
	}
	if len(rep.Errors) > 0 {
		return rep, fmt.Errorf("retention sweep: %d step error(s)", len(rep.Errors))
	}
	return rep, nil
}

// sweepSessions destroys sessions whose ExpiresAt has passed. Skipped
// (not an error) when no SessionManager is wired or the backend refuses
// ListAll (core.ErrUnsupportedOperation — a deliberate escape hatch for
// backends with too many sessions to enumerate).
func (s *RetentionSweeper) sweepSessions(ctx context.Context, cfg RetentionConfig, rep *RetentionReport) {
	if s.Sessions == nil {
		rep.Skipped = append(rep.Skipped, "sessions(not wired)")
		return
	}
	sessions, err := s.Sessions.ListAll(ctx)
	if errors.Is(err, core.ErrUnsupportedOperation) {
		rep.Skipped = append(rep.Skipped, "sessions(backend does not support ListAll)")
		return
	}
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("list sessions: %v", err))
		return
	}
	now := s.now()
	for _, sess := range sessions {
		s.maybeDestroySession(ctx, cfg, rep, sess, now)
	}
}

func (s *RetentionSweeper) maybeDestroySession(ctx context.Context, cfg RetentionConfig, rep *RetentionReport, sess *core.Session, now time.Time) {
	if sess == nil || sess.ExpiresAt.IsZero() || sess.ExpiresAt.After(now) {
		return
	}
	rep.SessionsExpiredFound++
	if cfg.DryRun || (cfg.MaxPerSweep > 0 && rep.SessionsDestroyed >= cfg.MaxPerSweep) {
		return
	}
	if err := s.Sessions.Destroy(ctx, sess.ID); err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("destroy session %s: %v", sess.ID, err))
		return
	}
	rep.SessionsDestroyed++
}

// sweepDormantAccounts walks the user roster and flags (or, when
// cfg.AutoEraseDormant is set, erases) accounts whose most recent session
// predates cfg.DormantAfter. It sources activity from ListAll (not
// ListByUser, which filters out already-expired sessions and would make a
// truly-dormant account's history invisible) in a single pass, then checks
// every user against that map — one Sessions query total, not one per user.
func (s *RetentionSweeper) sweepDormantAccounts(ctx context.Context, cfg RetentionConfig, rep *RetentionReport) {
	if s.Users == nil || s.Sessions == nil {
		rep.Skipped = append(rep.Skipped, "dormant_accounts(not wired)")
		return
	}
	users, err := s.Users.List(ctx)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("list users: %v", err))
		return
	}
	sessions, err := s.Sessions.ListAll(ctx)
	if errors.Is(err, core.ErrUnsupportedOperation) {
		rep.Skipped = append(rep.Skipped, "dormant_accounts(backend does not support ListAll)")
		return
	}
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("list sessions: %v", err))
		return
	}
	lastActive := lastActiveByUser(sessions)
	now := s.now()
	for _, u := range users {
		s.maybeFlagDormant(ctx, cfg, rep, u, lastActive, now)
	}
}

// lastActiveByUser reduces a raw session dump to each user's most recent
// CreatedAt — the "last active" proxy derived entirely from EXISTING session
// records (no new tracking).
func lastActiveByUser(sessions []*core.Session) map[string]time.Time {
	out := make(map[string]time.Time, len(sessions))
	for _, sess := range sessions {
		if sess == nil {
			continue
		}
		if sess.CreatedAt.After(out[sess.UserID]) {
			out[sess.UserID] = sess.CreatedAt
		}
	}
	return out
}

// maybeFlagDormant flags u as a dormant erasure-review candidate when its
// most recent session predates cfg.DormantAfter, and (only when
// cfg.AutoEraseDormant + an Eraser are both configured, and not DryRun)
// erases it. A user with zero session history is left alone — see
// RetentionConfig.DormantAfter doc for why absence of evidence isn't treated
// as evidence of dormancy.
func (s *RetentionSweeper) maybeFlagDormant(ctx context.Context, cfg RetentionConfig, rep *RetentionReport, u *core.User, lastActive map[string]time.Time, now time.Time) {
	if u == nil || u.ID == "" {
		return
	}
	last, seen := lastActive[u.ID]
	if !seen || now.Sub(last) < cfg.DormantAfter {
		return
	}
	rep.DormantAccountsFlagged = append(rep.DormantAccountsFlagged, u.ID)
	s.maybeEraseDormant(ctx, cfg, rep, u.ID)
}

func (s *RetentionSweeper) maybeEraseDormant(ctx context.Context, cfg RetentionConfig, rep *RetentionReport, userID string) {
	if !cfg.AutoEraseDormant || s.Eraser == nil || cfg.DryRun {
		return
	}
	if cfg.MaxPerSweep > 0 && rep.DormantAccountsErased >= cfg.MaxPerSweep {
		return
	}
	if _, err := s.Eraser.EraseSubject(ctx, userID, EraseOptions{}); err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("erase dormant account %s: %v", userID, err))
		return
	}
	rep.DormantAccountsErased++
}

// reportAuditRetention counts (never deletes) audit events older than
// cfg.AuditReportMaxAge, bounded by auditRetentionReportCap.
func (s *RetentionSweeper) reportAuditRetention(ctx context.Context, cfg RetentionConfig, rep *RetentionReport) {
	if s.Auditor == nil || s.Auditor.Sink() == nil {
		rep.Skipped = append(rep.Skipped, "audit_retention(not wired)")
		return
	}
	cutoff := s.now().Add(-cfg.AuditReportMaxAge)
	events, err := s.Auditor.Sink().Query(ctx, audit.Query{Until: cutoff, Limit: auditRetentionReportCap})
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Sprintf("count audit events past retention: %v", err))
		return
	}
	rep.AuditEventsPastRetention = len(events)
}

// RetentionSweepRequest is the optional POST body for the manual trigger.
type RetentionSweepRequest struct {
	// DryRun, when true, overrides cfg.DryRun for THIS call only — a one-way
	// safety override (it can only turn dry-run ON, never off an
	// operator-mandated dry-run-only configuration).
	DryRun bool `json:"dry_run"`
}

// bindOptionalJSON decodes an OPTIONAL JSON body: an empty body (io.EOF) is
// treated as "no overrides supplied", not an error, so a bare POST with no
// body is a valid way to trigger a sweep with the standing config unchanged.
// Any other decode error is a 400 invalid_request.
func bindOptionalJSON(ctx core.HandlerContext, v any) bool {
	if err := ctx.Bind(v); err != nil && !errors.Is(err, io.EOF) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return false
	}
	return true
}

// HandleAdminTriggerRetentionSweep serves POST
// /api/v1/admin/compliance/retention-sweep — runs ONE retention sweep pass on
// demand, in addition to whatever background interval the operator started
// via Server.RunDataRetentionSweep (if any). admin:write. Body (optional):
// {"dry_run": bool}.
func HandleAdminTriggerRetentionSweep(sweeper *RetentionSweeper, cfg RetentionConfig, log spi.Logger, ctx core.HandlerContext) {
	var req RetentionSweepRequest
	if !bindOptionalJSON(ctx, &req) {
		return
	}
	if req.DryRun {
		cfg.DryRun = true
	}
	rep, err := sweeper.Sweep(ctx.Request().Context(), cfg)
	if err != nil {
		log.Error("retention sweep had step errors", "error", err)
	}
	ctx.JSON(http.StatusOK, rep)
}
