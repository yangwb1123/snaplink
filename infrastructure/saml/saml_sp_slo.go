package saml

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/saml/sp"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// sloSPHandler is the SP-side Single Logout receiver: the UPSTREAM IdP
// redirects/POSTs a signed LogoutRequest here to log this server out. It
// validates the request against the boot-pinned IdP cert (inside the
// SPAuthenticator), terminates the matching LOCAL session(s) via the
// SessionManager, and returns a signed LogoutResponse to the IdP.
type sloSPHandler struct {
	authnsByName map[string]*sp.SPAuthenticator
	sessions     sso.SessionManager
	logger       spi.Logger
}

// serve handles GET/POST on the SP SLO endpoint (PathSAMLSPSLO). It is a
// session-mutating endpoint, so it stamps no-store headers at entry — including
// on the error path. SECURITY: it terminates a local session ONLY after the
// SPAuthenticator has signature-verified the LogoutRequest against the pinned
// IdP cert (an unsigned/forged request fails ProcessLogoutRequest → 400, no
// session touched). Oracle-safe: every validation failure collapses to one
// saml_request_invalid; a logout of a non-existent session still returns a
// Success LogoutResponse (no session-existence oracle).
func (h *sloSPHandler) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	redirectBinding := r.Method == http.MethodGet
	var samlRequest, relayState string
	switch r.Method {
	case http.MethodGet:
		samlRequest = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
			return
		}
		samlRequest = r.PostForm.Get("SAMLRequest")
		relayState = r.PostForm.Get("RelayState")
	default:
		writeError(w, http.StatusMethodNotAllowed, sso.ErrSAMLRequestInvalid)
		return
	}
	if samlRequest == "" {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	authn, err := h.dispatch(samlRequest, redirectBinding)
	if err != nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// The SPAuthenticator validates the LogoutRequest signature against the
	// PINNED IdP cert (the crux): the DETACHED §3.4.4.1 query-param signature for
	// the HTTP-Redirect binding (reconstructed from the raw query), or the
	// enveloped XML-DSig for HTTP-POST. A forged/unsigned request — or a replayed
	// or stale one — yields ErrLogoutInvalid → one collapsed code, NO session
	// terminated. r.URL.RawQuery carries the raw (still-encoded) redirect values
	// the detached-signature octet string is rebuilt from.
	subj, err := authn.ProcessLogoutRequest(samlRequest, relayState, redirectBinding, r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// Terminate ONLY the matching local session(s) for the subject (NameID),
	// optionally narrowed to the SessionIndex. Best-effort; existence is NOT
	// leaked — a Success response is returned regardless of whether a session
	// matched (no session-enumeration oracle).
	h.terminateLocalSessions(r.Context(), subj.NameID, subj.SessionIndex)

	// Acknowledge with a SIGNED LogoutResponse redirect to the IdP's SLO
	// endpoint. When the SP has no signing key or the IdP SLO endpoint is
	// unresolvable, fall back to a bare 200 (the local session is already dead;
	// we just can't acknowledge).
	respURL, err := authn.BuildLogoutResponseURL(subj.RequestID, relayState)
	if err != nil || respURL == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Location", respURL)
	w.WriteHeader(http.StatusFound)
}

// terminateLocalSessions destroys the local sessions for nameID (the SSO
// subject the SP created at ACS time), optionally narrowed to sessionIndex. It
// is scoped to the SUBJECT — never a global wipe. A sessionIndex that does not
// belong to the subject is ignored (ListByUser already bounds the set to the
// subject's sessions).
func (h *sloSPHandler) terminateLocalSessions(ctx context.Context, nameID, sessionIndex string) {
	sessions, err := h.sessions.ListByUser(ctx, nameID)
	if err != nil {
		h.logger.Error("saml: SP-SLO list sessions failed", "error", err)
		return
	}
	for _, s := range sessions {
		if s == nil {
			continue
		}
		if sessionIndex != "" && s.ID != sessionIndex {
			continue
		}
		if err := h.sessions.Destroy(ctx, s.ID); err != nil {
			h.logger.Error("saml: SP-SLO destroy session failed", "error", err)
		}
	}
}

// dispatch selects the SPAuthenticator (which upstream-IdP config) that handles
// this inbound SP-side LogoutRequest, BY ITS ISSUER — NOT by RelayState. In a
// FRONT-channel chain the RelayState is the IdP's unguessable chain-state id (no
// provider hint), so a RelayState-name lookup would miss with multiple SPConfigs
// wired and silently fail to terminate the session while the IdP chain still
// completes Success. Selecting by Issuer fixes that.
//
// SECURITY: the Issuer is decoded from the (as-yet-unverified) LogoutRequest and
// used ONLY as a LOOKUP KEY to pick the trust anchor. It is NEVER a trust
// decision: the chosen authenticator's ProcessLogoutRequest still fully validates
// the signature against that IdP's PINNED cert (and re-checks Issuer == pinned
// entity id). A forged/wrong Issuer just selects an authenticator whose cert won't
// validate the signature → rejected. The decode runs the same XXE-safe /
// bomb-bounded path ProcessLogoutRequest uses.
//
// Single-SPConfig is the fast path: exactly one authenticator is unambiguous, so
// it is used directly with no Issuer lookup (byte-identical to the prior behavior).
// No authenticator's pinned IdP entity id matching the Issuer → an error the
// caller maps to the one oracle-safe code (same 400 as today).
func (h *sloSPHandler) dispatch(samlRequest string, redirectBinding bool) (*sp.SPAuthenticator, error) {
	if len(h.authnsByName) == 1 {
		for _, a := range h.authnsByName {
			return a, nil
		}
	}
	issuer, err := sp.PeekLogoutRequestIssuer(samlRequest, redirectBinding)
	if err != nil {
		return nil, err
	}
	for _, a := range h.authnsByName {
		if a.IDPEntityID() == issuer {
			return a, nil
		}
	}
	return nil, errors.New("saml: no SP matched the LogoutRequest Issuer")
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{sso.KeyError: code})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set(sso.HeaderContentType, sso.ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
