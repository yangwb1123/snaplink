package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildsign"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// newSelfServiceExporter builds the /me/data-export exporter (GDPR Art. 15
// self-service), scoped at request time to the authenticated bearer's own
// subject by the handler. Consent + MFAEnrollments are NOT set here — those
// stores wire later (build ordering), so the caller retains this pointer and
// finalize late-binds them before serving (mirrors newSelfServiceEraser).
func newSelfServiceExporter(users core.UserProvider, sessions core.SessionManager) *compliance.Exporter {
	return &compliance.Exporter{Users: users, Sessions: sessions}
}

// rebindQuotaSessionConsumers replaces the raw manager captured before tenant
// wiring so internal quota_pending rows never appear in subject exports.
func (b *appBuilder) rebindQuotaSessionConsumers() {
	if b.dataExporter != nil {
		b.dataExporter.Sessions = b.sessionMgr
	}
}

// selfServiceAccountEraseOption wires POST /me/account/erase (GDPR Art. 17
// self-service) with a COMPLETE eraser (incl. refresh-token revocation across
// clients) so a self-deletion also cuts off the user's tokens.
// newSelfServiceEraser builds the /me/account/erase eraser. Consent +
// MFAEnrollments are NOT set here — those stores wire later (build ordering), so
// the caller retains this pointer and finalize late-binds them before serving.
func newSelfServiceEraser(users core.UserProvider, sessions core.SessionManager, refresh oauth.RefreshTokenSubjectIndex, clients core.ClientStore) *compliance.Eraser {
	return &compliance.Eraser{
		Users: users, Sessions: sessions, Refresh: refresh, Clients: clients,
	}
}

// wireEmailChangeStore adds the verified email-change token store after the
// sender is built and the account eraser exists.
func (b *appBuilder) wireEmailChangeStore() error {
	store, err := serverbuildstore.BuildEmailChangeStore(b.cfg.SelfService.EmailChange, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("self_service email_change store: %w", err)
	}
	if store == nil {
		return nil
	}
	if b.emailSender == nil {
		closeIfCloser(store)
		return errors.New("self_service.email_change requires smtp.enabled with a host")
	}
	b.opts = append(b.opts, sso.WithEmailChangeStore(store, 0))
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "email-change", store)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "email-change", store)
	if b.accountEraser != nil {
		if revoker, ok := store.(core.EmailChangeRevoker); ok {
			b.accountEraser.EmailChange = revoker
		}
	}
	b.logger.Info("self-service email change enabled", "backend", b.cfg.SelfService.EmailChange.Backend)
	return nil
}

// Compliance route prefixes. Mounted on the SSO router (so they share its
// middleware stack) and gated by AdminMiddleware via IsProtectedPath's
// /api/v1/compliance/ entry: GET export needs admin:read, POST erase
// needs admin:write (the middleware maps method -> scope).
const (
	complianceUsersPrefix  = "/api/v1/compliance/users/"
	complianceExportSuffix = "/export"
	complianceEraseSuffix  = "/erase"
)

func complianceCredentialStores(a *app) (core.PasswordCredentialDeleter, core.EmailChangeRevoker) {
	if a == nil || a.server == nil {
		return nil, nil
	}
	var passwordDeleter core.PasswordCredentialDeleter
	if deleter, ok := a.server.PasswordCredentialStore().(core.PasswordCredentialDeleter); ok {
		passwordDeleter = deleter
	}
	var emailChangeRevoker core.EmailChangeRevoker
	if revoker, ok := a.server.EmailChangeStore().(core.EmailChangeRevoker); ok {
		emailChangeRevoker = revoker
	}
	return passwordDeleter, emailChangeRevoker
}

// complianceDeps bundles the stores the GDPR workflows compose. Refresh may
// be nil when the configured refresh-token store can't enumerate by subject.
type complianceDeps struct {
	Users                   core.UserProvider
	Sessions                core.SessionManager
	Refresh                 oauth.RefreshTokenSubjectIndex
	Clients                 core.ClientStore
	Consent                 core.ConsentStore
	MFAEnrollments          core.MFAEnrollmentStore
	PasswordReset           core.PasswordResetRevoker
	EmailChange             core.EmailChangeRevoker
	PasswordCredential      core.PasswordCredentialDeleter
	Notifications           core.NotificationStore
	NotificationPreferences core.NotificationPreferenceStore
	Recorder                *audit.Recorder
}

// mountComplianceRoutes registers the subject export + erase endpoints.
// No-op without a UserProvider (nothing to act on).
func mountComplianceRoutes(srv *sso.Server, deps *complianceDeps) error {
	if deps == nil || deps.Users == nil {
		return nil
	}
	if err := srv.Handle(http.MethodGet, complianceUsersPrefix+":id"+complianceExportSuffix, complianceExportHandler(deps)); err != nil {
		return err
	}
	return srv.Handle(http.MethodPost, complianceUsersPrefix+":id"+complianceEraseSuffix, complianceEraseHandler(deps))
}

// complianceUserID extracts the single {id} segment between the prefix
// and the action suffix, or "" if the path doesn't match exactly.
func complianceUserID(path, suffix string) string {
	if !strings.HasPrefix(path, complianceUsersPrefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, complianceUsersPrefix), suffix)
	if id == "" || strings.Contains(id, "/") {
		return ""
	}
	return id
}

func complianceExportHandler(deps *complianceDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := complianceUserID(r.URL.Path, complianceExportSuffix)
		if id == "" {
			writeComplianceError(w, http.StatusBadRequest, "invalid_path")
			return
		}
		exporter := &compliance.Exporter{
			Users:    deps.Users,
			Sessions: deps.Sessions,
			// Closes the Eraser/Exporter asymmetry: the admin erase path already
			// clears consent + MFA enrollments (below), so Art. 15 export must
			// surface the same two domains before they're gone.
			Extra: compliance.SubjectExporters(deps.Consent, deps.MFAEnrollments),
		}
		bundle, opErr := exporter.ExportSubject(r.Context(), id)
		recordCompliance(deps.Recorder, audit.EventAdminSubjectExported, id, r, opErr)
		// Best-effort: deliver whatever was gathered even on partial
		// store errors (the audit event records the failure).
		writeComplianceJSON(w, http.StatusOK, bundle)
	}
}

// eraseRequest is the optional POST body for an erase.
type eraseRequest struct {
	DryRun bool `json:"dry_run"`
}

// eraseResponse is the JSON view of compliance.Report (whose Errors are
// []error and don't marshal cleanly) — errors render as strings.
type eraseResponse struct {
	UserID               string   `json:"user_id"`
	DryRun               bool     `json:"dry_run"`
	RefreshTokensDeleted int      `json:"refresh_tokens_deleted"`
	SessionsDestroyed    int      `json:"sessions_destroyed"`
	ConsentRevoked       int      `json:"consent_revoked"`
	MFAFactorsRemoved    int      `json:"mfa_factors_removed"`
	ResetTokensRevoked   int      `json:"reset_tokens_revoked"`
	UserDeleted          bool     `json:"user_deleted"`
	Skipped              []string `json:"skipped,omitempty"`
	Errors               []string `json:"errors,omitempty"`
}

func newComplianceEraser(deps *complianceDeps) *compliance.Eraser {
	return &compliance.Eraser{
		Users:                   deps.Users,
		Sessions:                deps.Sessions,
		Refresh:                 deps.Refresh,
		Clients:                 deps.Clients,
		Consent:                 deps.Consent,
		MFAEnrollments:          deps.MFAEnrollments,
		PasswordReset:           deps.PasswordReset,
		EmailChange:             deps.EmailChange,
		PasswordCredentials:     deps.PasswordCredential,
		Notifications:           deps.Notifications,
		NotificationPreferences: deps.NotificationPreferences,
	}
}

func complianceEraseHandler(deps *complianceDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := complianceUserID(r.URL.Path, complianceEraseSuffix)
		if id == "" {
			writeComplianceError(w, http.StatusBadRequest, "invalid_path")
			return
		}
		var req eraseRequest
		if r.Body != nil {
			// Optional body; an empty/absent body is a non-dry-run erase.
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		eraser := newComplianceEraser(deps)
		rep, opErr := eraser.EraseSubject(r.Context(), id, compliance.EraseOptions{DryRun: req.DryRun})
		recordCompliance(deps.Recorder, audit.EventAdminSubjectErased, id, r, opErr)

		resp := eraseResponse{
			UserID:               rep.UserID,
			DryRun:               rep.DryRun,
			RefreshTokensDeleted: rep.RefreshTokensDeleted,
			SessionsDestroyed:    rep.SessionsDestroyed,
			ConsentRevoked:       rep.ConsentRevoked,
			MFAFactorsRemoved:    rep.MFAFactorsRemoved,
			ResetTokensRevoked:   rep.ResetTokensRevoked,
			UserDeleted:          rep.UserDeleted,
			Skipped:              rep.Skipped,
		}
		for _, e := range rep.Errors {
			resp.Errors = append(resp.Errors, e.Error())
		}
		// A partial failure still erased some data; surface it as 207 so
		// operators notice without implying nothing happened.
		code := http.StatusOK
		if opErr != nil {
			code = http.StatusMultiStatus
		}
		writeComplianceJSON(w, code, resp)
	}
}

// recordCompliance emits the audit event for a compliance action,
// stamping the data subject + admin actor. Outcome follows opErr.
func recordCompliance(rec *audit.Recorder, typ audit.EventType, subjectID string, r *http.Request, opErr error) {
	if rec == nil {
		return
	}
	e := &audit.Event{
		Type:      typ,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(),
	}
	if actor, clientID, ok := sso.AdminActorFromContext(r.Context()); ok {
		e.ActorID = actor
		e.ClientID = clientID
	}
	audit.SetMeta(e, "subject", subjectID)
	if opErr != nil {
		e.Outcome = audit.OutcomeFailure
		e.Reason = opErr.Error()
	}
	rec.Record(context.Background(), e)
}

func writeComplianceJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeComplianceError(w http.ResponseWriter, code int, reason string) {
	writeComplianceJSON(w, code, map[string]string{"error": reason})
}

// lateBindComplianceStores sets Consent + MFAEnrollments + PasswordReset on
// the self-service eraser (Consent + MFAEnrollments on the exporter too)
// AFTER wireFinalOptions has wired those stores. Both compliance.Eraser/
// Exporter pointers are constructed early in wireDomains (before
// consentStore/mfaEnrollStore/passwordResetRevoker exist), so a one-shot
// assignment at construction time would silently capture nil — the SDK
// holds each by pointer and reads these fields at request time, so setting
// them here (once, right before NewServer) makes self-erasure AND
// self-export agree with the admin compliance routes on what "the
// subject's consent + MFA + pending reset-token data" is. Relocated from
// build_app.go (which was at the line budget) to sit beside the rest of
// this file's compliance-route wiring.
func (b *appBuilder) lateBindComplianceStores() {
	if b.accountEraser != nil {
		b.accountEraser.Consent = b.consentStore
		b.accountEraser.MFAEnrollments = b.mfaEnrollStore
		b.accountEraser.PasswordReset = b.passwordResetRevoker
		if deleter, ok := b.passwordStore.(core.PasswordCredentialDeleter); ok {
			b.accountEraser.PasswordCredentials = deleter
		}
	}
	if b.dataExporter != nil {
		b.dataExporter.Extra = compliance.SubjectExporters(b.consentStore, b.mfaEnrollStore)
	}
}

// lateBindComplianceServerStores attaches optional notification stores after
// the constructed Server exposes the shared pair. The eraser pointer is
// retained by the self-service option and is safe to update before serving.
func (b *appBuilder) lateBindComplianceServerStores(srv *sso.Server) {
	if b.accountEraser == nil || srv == nil {
		return
	}
	b.accountEraser.Notifications = srv.NotificationStore()
	b.accountEraser.NotificationPreferences = srv.NotificationPreferenceStore()
}
