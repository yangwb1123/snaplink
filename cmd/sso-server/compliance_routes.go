package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// selfServiceDataExportOption wires GET /me/data-export (GDPR Art. 15 self-
// service) from the same stores the admin compliance export uses — scoped at
// request time to the authenticated bearer's own subject by the handler.
func selfServiceDataExportOption(users core.UserProvider, sessions core.SessionManager) sso.Option {
	return sso.WithSelfServiceDataExport(&compliance.Exporter{Users: users, Sessions: sessions})
}

// selfServiceAccountEraseOption wires POST /me/account/erase (GDPR Art. 17
// self-service) with a COMPLETE eraser (incl. refresh-token revocation across
// clients) so a self-deletion also cuts off the user's tokens.
func selfServiceAccountEraseOption(users core.UserProvider, sessions core.SessionManager, refresh oauth.RefreshTokenSubjectIndex, clients core.ClientStore) sso.Option {
	return sso.WithSelfServiceAccountErasure(&compliance.Eraser{
		Users: users, Sessions: sessions, Refresh: refresh, Clients: clients,
	})
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

// complianceDeps bundles the stores the GDPR workflows compose. Refresh
// may be nil when the configured refresh-token store can't enumerate by
// subject (the Eraser skips it then).
type complianceDeps struct {
	Users    core.UserProvider
	Sessions core.SessionManager
	Refresh  oauth.RefreshTokenSubjectIndex
	Clients  core.ClientStore
	Recorder *audit.Recorder
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
		exporter := &compliance.Exporter{Users: deps.Users, Sessions: deps.Sessions}
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
	UserDeleted          bool     `json:"user_deleted"`
	Skipped              []string `json:"skipped,omitempty"`
	Errors               []string `json:"errors,omitempty"`
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
		eraser := &compliance.Eraser{
			Users:    deps.Users,
			Sessions: deps.Sessions,
			Refresh:  deps.Refresh,
			Clients:  deps.Clients,
		}
		rep, opErr := eraser.EraseSubject(r.Context(), id, compliance.EraseOptions{DryRun: req.DryRun})
		recordCompliance(deps.Recorder, audit.EventAdminSubjectErased, id, r, opErr)

		resp := eraseResponse{
			UserID:               rep.UserID,
			DryRun:               rep.DryRun,
			RefreshTokensDeleted: rep.RefreshTokensDeleted,
			SessionsDestroyed:    rep.SessionsDestroyed,
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeComplianceError(w http.ResponseWriter, code int, reason string) {
	writeComplianceJSON(w, code, map[string]string{"error": reason})
}
