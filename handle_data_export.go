package sso

import (
	"net/http"

	"github.com/snaplink/sso/audit"
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
