// Package appcore is the shared business logic both examples/embedded-app
// and examples/remote-app depend on. The point of these two examples is
// that they have identical business code — they differ only in how the
// ssoclient interfaces are wired at startup.
//
// The handler implements a trivial "items list" endpoint:
//
//  1. Read the bearer token from Authorization.
//  2. ValidateToken → get a Subject.
//  3. Check the "items:read" permission for that Subject.
//  4. Record an audit event.
//  5. Return JSON.
package appcore

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/ssoclient"
)

const requiredPermission = "items:read"

// Handler holds the three ssoclient interfaces the business code needs.
// Construct one with the local or remote implementations of your choice.
type Handler struct {
	Auth  ssoclient.AuthClient
	Authz ssoclient.AuthzClient
	Audit ssoclient.AuditClient
}

// ListItems is the only endpoint. It returns 401 / 403 / 200 depending on
// auth state and is fully decoupled from the local-vs-remote choice.
func (h *Handler) ListItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}

	subj, err := h.Auth.ValidateToken(ctx, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	clientID := firstAudience(subj)
	allowed, err := h.Authz.Check(ctx, &ssoclient.CheckRequest{
		SubjectID:  subj.ID,
		ClientID:   clientID,
		Permission: requiredPermission,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authz_failed")
		return
	}
	if !allowed {
		_ = h.Audit.Record(ctx, &ssoclient.Event{
			Type:     audit.EventType("items_list"),
			Outcome:  audit.OutcomeFailure,
			ActorID:  subj.ID,
			ClientID: clientID,
			Reason:   "permission_denied",
		})
		writeError(w, http.StatusForbidden, "permission_denied")
		return
	}

	_ = h.Audit.Record(ctx, &ssoclient.Event{
		Type:     audit.EventType("items_list"),
		Outcome:  audit.OutcomeSuccess,
		ActorID:  subj.ID,
		ClientID: clientID,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"items": []string{"alpha", "beta", "gamma"},
		"user":  subj.ID,
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func firstAudience(s *ssoclient.Subject) string {
	if s == nil || len(s.Audience) == 0 {
		return ""
	}
	return s.Audience[0]
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errCode string) {
	writeJSON(w, code, map[string]string{"error": errCode})
}

// Verify the ssoclient package is loaded — keeps `errors` reachable in
// case future edits need it.
var _ = errors.New
