package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/snaplink/sso/domains/authenticators/webauthn"
)

func webauthnBeginRegistrationHandler(h *webauthn.Helper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBeginRequest(r)
		if err != nil {
			writeWebAuthnError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.Username == "" {
			writeWebAuthnError(w, http.StatusBadRequest, "invalid_request", "username required")
			return
		}
		creation, sessionID, err := h.BeginRegistration(r.Context(), req.Username, req.DisplayName)
		if err != nil {
			writeWebAuthnError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		body, err := json.Marshal(creation)
		if err != nil {
			writeWebAuthnError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		writeWebAuthnJSON(w, http.StatusOK, webauthnBeginRegistrationResponse{
			SessionID: sessionID,
			Options:   body,
		})
	}
}

func webauthnFinishRegistrationHandler(deps *webauthnDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			writeWebAuthnError(w, http.StatusBadRequest, "invalid_request", "session_id required")
			recordWebAuthnRegistration(deps, "failure")
			return
		}
		cred, err := deps.Helper.FinishRegistration(r.Context(), sessionID, r)
		if err != nil {
			// Attestation-policy denial is a distinct disposition: the
			// authenticator verified fine but its AAGUID isn't permitted.
			// Surface a generic attestation_denied (403) to the client —
			// the AAGUID + policy mode go to the audit trail, not the wire
			// (oracle-reasonable: the user learns their authenticator isn't
			// approved, not the policy internals).
			var denied *webauthn.AttestationDeniedError
			if errors.As(err, &denied) {
				recordWebAuthnAttestationDenied(deps, r, denied)
				writeWebAuthnError(w, http.StatusForbidden, codeAttestationDenied, "authenticator not permitted")
				recordWebAuthnRegistration(deps, "failure")
				return
			}
			status, code := webauthnErrorStatus(err)
			writeWebAuthnError(w, status, code, err.Error())
			recordWebAuthnRegistration(deps, "failure")
			return
		}
		// Emit the success audit (carrying the AAGUID for operator
		// allowlist curation) ONLY when the attestation policy is active.
		// Without a policy the registration path stays byte-identical to a
		// pre-policy build — no new audit event on success (the existing
		// metric still fires below).
		if deps.Helper.AttestationPolicyEnabled() {
			recordWebAuthnRegistered(deps, r, cred)
		}
		writeWebAuthnJSON(w, http.StatusOK, webauthnFinishRegistrationResponse{
			CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		})
		recordWebAuthnRegistration(deps, "success")
	}
}

// codeAttestationDenied is the wire error code returned when the WebAuthn
// attestation policy rejects an authenticator (403). Documented in
// docs/error-codes.md; SPAs branch on the code, never the description.
const codeAttestationDenied = "attestation_denied"

// recordWebAuthnRegistered emits the success audit event carrying the
// registered authenticator's AAGUID (a public model identifier, safe in
// metadata) so an operator running an attestation allowlist can curate it.
// Nil-safe when no recorder is wired.

func webauthnBeginLoginHandler(h *webauthn.Helper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBeginRequest(r)
		if err != nil {
			writeWebAuthnError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.Username == "" {
			writeWebAuthnError(w, http.StatusBadRequest, "invalid_request", "username required")
			return
		}
		assertion, sessionID, err := h.BeginLogin(r.Context(), req.Username)
		if err != nil {
			status, code := webauthnErrorStatus(err)
			writeWebAuthnError(w, status, code, err.Error())
			return
		}
		body, err := json.Marshal(assertion)
		if err != nil {
			writeWebAuthnError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		writeWebAuthnJSON(w, http.StatusOK, webauthnBeginLoginResponse{
			SessionID: sessionID,
			Options:   body,
		})
	}
}

func webauthnFinishLoginHandler(deps *webauthnDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			writeWebAuthnError(w, http.StatusBadRequest, "invalid_request", "session_id required")
			recordWebAuthnAssertion(deps, "failure")
			return
		}
		user, cred, err := deps.Helper.FinishLogin(r.Context(), sessionID, r)
		if err != nil {
			status, code := webauthnErrorStatus(err)
			writeWebAuthnError(w, status, code, err.Error())
			recordWebAuthnAssertion(deps, "failure")
			return
		}
		resp := webauthnFinishLoginResponse{
			Username:     user.Name,
			CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		}
		// Optional token issuance: when client_id is supplied AND
		// the cmd has a ClientStore + TokenIssuers wired, mint an
		// access token for the authenticated subject. Missing
		// client_id falls through to credential-only v1 behavior so
		// embedders integrating their own token path aren't
		// disturbed.
		clientID := r.URL.Query().Get("client_id")
		if clientID != "" && deps.ClientStore != nil && len(deps.TokenIssuers) > 0 {
			if !applyWebAuthnTokenIssuance(w, r, deps, clientID, user.Name, &resp) {
				return
			}
		}
		writeWebAuthnJSON(w, http.StatusOK, resp)
		recordWebAuthnAssertion(deps, "success")
	}
}

// applyWebAuthnTokenIssuance mints the optional token bundle for the
// crypto-verified user and folds it into resp. Returns false when issuance
// failed (the error response has been written and the assertion-success metric
// already recorded) so the caller returns without writing the v1 body — token
// issuance failure post-assertion is still a verified user, so the failure is
// labelled via the existing http_requests_total status_class signal, NOT a
// double-counted assertion failure.
func applyWebAuthnTokenIssuance(w http.ResponseWriter, r *http.Request, deps *webauthnDeps, clientID, userName string, resp *webauthnFinishLoginResponse) bool {
	result, err := issueWebAuthnToken(r, deps, clientID, userName)
	if err != nil {
		status, code := webauthnIssueErrorStatus(err)
		writeWebAuthnError(w, status, code, err.Error())
		recordWebAuthnAssertion(deps, "success")
		return false
	}
	resp.AccessToken = result.AccessToken
	resp.TokenType = result.TokenType
	resp.ExpiresIn = result.ExpiresIn
	resp.Scope = result.Scope
	resp.RefreshToken = result.RefreshToken
	resp.IDToken = result.IDToken
	return true
}

// errWebAuthnClientNotFound is returned by issueWebAuthnToken when
// the requested client_id isn't registered. Mapped to 400
// invalid_client so the client surface mirrors the OAuth /token
// endpoint shape.
var errWebAuthnClientNotFound = errors.New("webauthn: client not found")

// errWebAuthnClientInactive is returned when the client exists but
// has Active=false — same disposition as login through /auth/login.
var errWebAuthnClientInactive = errors.New("webauthn: client inactive")

// errWebAuthnNoIssuer is returned when the client's token_strategy
// doesn't have a registered issuer. Server misconfiguration; 500.
var errWebAuthnNoIssuer = errors.New("webauthn: no token issuer for client strategy")

// errWebAuthnIDToken is returned when oidc.IDTokenIssuer.IssueIDToken
// fails for a client that wanted openid scope. Surfaced as 500 since
// the configured oidc.IDTokenIssuer should be healthy.
var errWebAuthnIDToken = errors.New("webauthn: id_token issuance failed")

// errWebAuthnRefreshToken is returned when oauth.RefreshTokenStore.Issue
// fails for a client that wanted offline_access. Surfaced as 500.
var errWebAuthnRefreshToken = errors.New("webauthn: refresh_token issuance failed")

// errWebAuthnResidency is the sentinel for a residency-denied WebAuthn mint
// (the tenant's ResidencyPolicy forbids minting from this serving region).
// Unlike the other errWebAuthn* sentinels its HTTP wire code is DYNAMIC —
// region_not_allowed vs residency_violation, decided by the server's residency
// engine — so it's wrapped in a webauthnResidencyError carrying that code; the
// sentinel itself only lets webauthnIssueErrorStatus recognize the class.
var errWebAuthnResidency = errors.New("webauthn: residency denied")

// webauthnResidencyError carries the residency engine's dynamic wire code
// (region_not_allowed / residency_violation) so webauthnIssueErrorStatus can
// surface it on the 403 WITHOUT collapsing the two distinct governance codes
// to a generic one — mirroring residencyGateLogin's authz-error shape on the
// in-pipeline login path. Wraps errWebAuthnResidency for errors.Is.
type webauthnResidencyError struct{ code string }
