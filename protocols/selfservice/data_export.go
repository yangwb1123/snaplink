package selfservice

import (
	"net/http"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// HandleMyDataExport serves GET /me/data-export — the GDPR Art. 15 self-service
// export. It assembles a portable bundle of the AUTHENTICATED bearer's OWN data
// (scoped to their subject — never an arbitrary user, unlike the admin-gated
// /api/v1/compliance export) and returns it as JSON. Credential-adjacent:
// no-store headers. Emits subject_data_exported (the bundle is never recorded).
func HandleMyDataExport(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateAccess(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	userID := claims.Subject
	exporter := d.DataExporter()
	if exporter == nil {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrInternal))
		return
	}
	bundle, opErr := exporter.ExportSubject(ctx.Request().Context(), userID)
	if bundle == nil {
		d.Logger().Error("self-service data export failed", "user_id", userID, "error", opErr)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if opErr != nil {
		d.Logger().Error("self-service data export partial failure", "user_id", userID, "error", opErr)
	}
	if aud := d.Auditor(); aud != nil {
		evt := &audit.Event{
			Type:    audit.EventSubjectDataExported,
			Outcome: audit.OutcomeSuccess,
			ActorID: userID,
			ActorIP: audit.ClientIP(ctx.Request()),
		}
		if opErr != nil {
			audit.SetMeta(evt, "partial", "true")
		}
		aud.Record(ctx.Request().Context(), evt)
	}
	ctx.JSON(http.StatusOK, bundle)
}

// HandleMyAccountErase serves POST /me/account/erase — GDPR Art. 17 self-service
// erasure of the AUTHENTICATED bearer's OWN account (sessions + refresh tokens +
// user record), scoped to their subject. Body: {confirm, dry_run}. The caller
// MUST echo their own subject in `confirm` to authorize an irreversible delete
// (guards against accidental / CSRF-driven deletion). dry_run previews without
// mutating. Best-effort per-step (a store error doesn't strand the rest);
// failures are recorded in the audit event. Credential-adjacent: no-store.
func HandleMyAccountErase(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateWrite(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	userID := claims.Subject
	var req struct {
		Confirm string `json:"confirm"`
		DryRun  bool   `json:"dry_run"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if !req.DryRun && req.Confirm != userID {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrConfirmationRequired))
		return
	}
	eraser := d.AccountEraser()
	if eraser == nil {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrInternal))
		return
	}
	report, _ := eraser.EraseSubject(ctx.Request().Context(), userID, compliance.EraseOptions{DryRun: req.DryRun})
	if report == nil {
		d.Logger().Error("self-service account erase returned no report", "user_id", userID)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	RecordSelfErase(d, ctx, userID, report)
	if !req.DryRun {
		// A dry run previews without mutating anything — only a REAL erase is
		// the definitive session end Clear-Site-Data is for.
		d.ClearSiteData(ctx)
	}
	ctx.JSON(http.StatusOK, eraseReportResponse(report))
}

// eraseReportResponse is the JSON view of a compliance.Report for the
// self-service erase response. Split out of HandleMyAccountErase to stay
// under the function-length budget.
func eraseReportResponse(report *compliance.Report) map[string]any {
	return map[string]any{
		"user_id":                report.UserID,
		"dry_run":                report.DryRun,
		"refresh_tokens_deleted": report.RefreshTokensDeleted,
		"sessions_destroyed":     report.SessionsDestroyed,
		"consent_revoked":        report.ConsentRevoked,
		"mfa_factors_removed":    report.MFAFactorsRemoved,
		"reset_tokens_revoked":   report.ResetTokensRevoked,
		"user_deleted":           report.UserDeleted,
		"skipped":                report.Skipped,
	}
}
