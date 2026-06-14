package sso

import (
	"fmt"
	"net/http"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/compliance"
	"github.com/snaplink/sso/core"
)

// handleMyDataExport serves GET /me/data-export — the GDPR Art. 15 self-service
// export. It assembles a portable bundle of the AUTHENTICATED bearer's OWN data
// (scoped to their subject — never an arbitrary user, unlike the admin-gated
// /api/v1/compliance export) and returns it as JSON. Credential-adjacent:
// no-store headers. Emits subject_data_exported (the bundle is never recorded).
func (s *Server) handleMyDataExport(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	bundle, opErr := s.dataExporter.ExportSubject(ctx.Request().Context(), userID)
	if bundle == nil {
		// Only happens on a hard failure (e.g. empty userID, which can't occur
		// after meSubjectOrChallenge) — nothing to deliver.
		s.logger.Error("self-service data export failed", "user_id", userID, "error", opErr)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	// Best-effort: ExportSubject returns a (possibly partial) non-nil bundle
	// even when a single store errored — deliver it and record the partial
	// failure in the audit event, matching the admin export's contract.
	if opErr != nil {
		s.logger.Error("self-service data export partial failure", "user_id", userID, "error", opErr)
	}
	if s.auditor != nil {
		evt := &audit.Event{
			Type:    audit.EventSubjectDataExported,
			Outcome: audit.OutcomeSuccess,
			ActorID: userID,
			ActorIP: audit.ClientIP(ctx.Request()),
		}
		if opErr != nil {
			audit.SetMeta(evt, "partial", "true")
		}
		s.auditor.Record(ctx.Request().Context(), evt)
	}
	ctx.JSON(http.StatusOK, bundle)
}

// handleMyAccountErase serves POST /me/account/erase — GDPR Art. 17 self-service
// erasure of the AUTHENTICATED bearer's OWN account (sessions + refresh tokens +
// user record), scoped to their subject. Body: {confirm, dry_run}. The caller
// MUST echo their own subject in `confirm` to authorize an irreversible delete
// (guards against accidental / CSRF-driven deletion). dry_run previews without
// mutating. Best-effort per-step (a store error doesn't strand the rest);
// failures are recorded in the audit event. Credential-adjacent: no-store.
func (s *Server) handleMyAccountErase(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	var req struct {
		Confirm string `json:"confirm"`
		DryRun  bool   `json:"dry_run"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	// Confirmation guard: the caller must echo their own subject. A real (non
	// dry-run) erase without it is refused — accidental/CSRF protection for an
	// irreversible action.
	if !req.DryRun && req.Confirm != userID {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrConfirmationRequired))
		return
	}
	report, _ := s.accountEraser.EraseSubject(ctx.Request().Context(), userID, compliance.EraseOptions{DryRun: req.DryRun})
	if report == nil {
		s.logger.Error("self-service account erase returned no report", "user_id", userID)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordSelfErase(ctx, userID, report)
	ctx.JSON(http.StatusOK, map[string]any{
		"user_id":                report.UserID,
		"dry_run":                report.DryRun,
		"refresh_tokens_deleted": report.RefreshTokensDeleted,
		"sessions_destroyed":     report.SessionsDestroyed,
		"user_deleted":           report.UserDeleted,
		"skipped":                report.Skipped,
	})
}

func (s *Server) recordSelfErase(ctx HandlerContext, userID string, report *compliance.Report) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventSubjectSelfErased,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "dry_run", fmt.Sprintf("%t", report.DryRun))
	audit.SetMeta(evt, "sessions_destroyed", fmt.Sprintf("%d", report.SessionsDestroyed))
	audit.SetMeta(evt, "refresh_tokens_deleted", fmt.Sprintf("%d", report.RefreshTokensDeleted))
	audit.SetMeta(evt, "user_deleted", fmt.Sprintf("%t", report.UserDeleted))
	if err := report.Err(); err != nil {
		evt.Outcome = audit.OutcomeFailure
		evt.Reason = err.Error()
	}
	s.auditor.Record(ctx.Request().Context(), evt)
}
