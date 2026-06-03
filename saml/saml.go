package saml

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/saml/sp"
	"github.com/snaplink/sso/spi"
)

// Deps is the ROOT-module-typed dependency bundle saml.Build needs. Every
// field is a stdlib type, an sso (root-module) type, or an spi type — there is
// NO cmd/sso-server (package main) type here, because a separate module's
// package cannot import package main. The operator's forked main (which DOES
// have cmd's SAMLServerDeps) constructs a Deps from its SAMLServerDeps fields
// inside the factory closure (see the package doc for the copy-pasteable
// adaptation).
//
// Deps mirrors the shape of cmd's SAMLServerDeps so the adaptation is a
// field-for-field copy.
type Deps struct {
	// ClientStore / SessionManager / UserProvider are the same stores the rest
	// of the server reads, so a SAML login lands on the one identity model.
	// SessionManager + UserProvider are REQUIRED by the ACS handler (it upserts
	// the user + creates the session through them); ClientStore is carried for
	// parity + future per-client SAML policy. SessionManager nil ⇒ Build errors.
	ClientStore    sso.ClientStore
	SessionManager sso.SessionManager
	UserProvider   sso.UserProvider

	// IssuerForClient is the server's per-tenant access-token issuer selector
	// (tenant -> client strategy -> default), carried for parity with cmd's
	// SAMLServerDeps. The SP side authenticates + creates a session; it does
	// NOT mint an access token in this build (the blueprint's ACS returns a
	// session id), so this is reserved for a token-minting extension and may be
	// nil.
	IssuerForClient func(c *sso.Client) (string, sso.TokenIssuer, error)

	// Issuer is the configured AS issuer URL (carried for parity; unused by the
	// session-only ACS).
	Issuer string

	// Logger is the server logger. Nil ⇒ a no-op logger is used.
	Logger spi.Logger
}

// Config wraps the per-IdP SP configs the operator wants to wire. One SPConfig
// yields one SPAuthenticator; the ACS handler dispatches a POSTed assertion to
// the right authenticator by a provider hint in RelayState (or the single SP
// when only one is configured).
type Config struct {
	SPs []sp.SPConfig
}

// HandlerSpec is one HTTP route saml.Build contributes. It mirrors cmd's
// SAMLHandler field-for-field so the operator maps []saml.HandlerSpec onto
// []main.SAMLHandler trivially. The cmd mounts each via *sso.Server.Handle so
// they share the built-in middleware stack.
type HandlerSpec struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// BuildResult is everything saml.Build produces: the SP-side authenticators the
// operator registers (so /auth/login?provider=<name> redirects to the IdP) and
// the HTTP routes (the ACS callback) the operator mounts. The operator adapts
// this onto cmd's SAMLHandlerSet.
type BuildResult struct {
	Authenticators []sso.Authenticator
	Handlers       []HandlerSpec
}

// Build constructs an SPAuthenticator per SPConfig and the single
// POST /auth/saml/callback ACS handler, returning them as importable root-typed
// results for the operator to wire. A construction error (bad SP config,
// unresolved IdP trust anchor, missing required dep) fails the operator's boot
// closed.
func Build(deps Deps, cfg Config) (*BuildResult, error) {
	if deps.SessionManager == nil {
		return nil, errors.New("saml: SessionManager required (the ACS handler creates the session)")
	}
	if deps.UserProvider == nil {
		return nil, errors.New("saml: UserProvider required (the ACS handler upserts the user)")
	}
	if len(cfg.SPs) == 0 {
		return nil, errors.New("saml: at least one SP config required")
	}

	logger := deps.Logger
	if logger == nil {
		logger = spi.NopLogger{}
	}

	authnsByName := make(map[string]*sp.SPAuthenticator, len(cfg.SPs))
	authns := make([]sso.Authenticator, 0, len(cfg.SPs))
	for i := range cfg.SPs {
		a, err := sp.NewSPAuthenticator(cfg.SPs[i])
		if err != nil {
			return nil, fmt.Errorf("saml: build SP %q: %w", cfg.SPs[i].Name, err)
		}
		if _, dup := authnsByName[a.Name()]; dup {
			return nil, fmt.Errorf("saml: duplicate SP name %q", a.Name())
		}
		authnsByName[a.Name()] = a
		authns = append(authns, a)
	}

	acs := &acsHandler{
		authnsByName: authnsByName,
		sessions:     deps.SessionManager,
		users:        deps.UserProvider,
		logger:       logger,
	}

	return &BuildResult{
		Authenticators: authns,
		Handlers: []HandlerSpec{{
			Method:  http.MethodPost,
			Path:    sso.PathSAMLSSOCallback, // "/auth/saml/callback"
			Handler: acs.serve,
		}},
	}, nil
}

// acsHandler is the SP Assertion Consumer Service: it receives the IdP's POSTed
// SAML Response, validates the assertion via the matching SPAuthenticator, and
// on success upserts the user + creates a session.
type acsHandler struct {
	authnsByName map[string]*sp.SPAuthenticator
	sessions     sso.SessionManager
	users        sso.UserProvider
	logger       spi.Logger
}

// serve handles POST /auth/saml/callback. It is a credential-bearing endpoint
// (it mints session state), so it stamps no-store headers at entry — including
// on the error path — the same RFC 6749 §5.1 treatment the SDK applies to
// /token, /userinfo, /auth/login. On an invalid assertion it returns 400 with
// ONLY {"error":"saml_assertion_invalid"} (oracle-safe: no cause detail).
func (h *acsHandler) serve(w http.ResponseWriter, r *http.Request) {
	// no-store on every path, before any branch (a cached cross-user ACS
	// response — success or 401/400 — would be catastrophic).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, sso.ErrSAMLAssertionInvalid)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLAssertionInvalid)
		return
	}

	samlResponse := r.PostForm.Get("SAMLResponse")
	relayState := r.PostForm.Get("RelayState")
	if samlResponse == "" {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLAssertionInvalid)
		return
	}

	authn, err := h.dispatch(relayState)
	if err != nil {
		// No SP matched the relay hint (or multiple SPs and no hint). This is a
		// request-shaping failure, but we still collapse to the single
		// assertion-invalid code so the ACS exposes no provider-enumeration
		// oracle.
		writeError(w, http.StatusBadRequest, sso.ErrSAMLAssertionInvalid)
		return
	}

	result, err := authn.ProcessAssertion(r.Context(), samlResponse, relayState)
	if err != nil {
		// ProcessAssertion already collapsed every validation failure to the
		// single oracle-safe error; map it to the wire code with no detail.
		writeError(w, http.StatusBadRequest, sso.ErrSAMLAssertionInvalid)
		return
	}

	// Upsert the user onto the one identity model (mirrors the SDK login
	// orchestrator's finishLogin: ID from the resolved UserID, ExternalID +
	// Provider + Attributes from the assertion).
	if err := h.users.CreateOrUpdate(r.Context(), &sso.User{
		ID:         result.UserID,
		ExternalID: result.ExternalID,
		Provider:   result.Provider,
		Attributes: result.Attributes,
	}); err != nil {
		h.logger.Error("saml: upsert user failed", "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrInternal)
		return
	}

	// Create the session through the SessionManager (NOT a raw store) so the
	// session lands with the same lifecycle (expiry/refresh/revoke) as every
	// other login.
	session, err := h.sessions.Create(r.Context(), result.UserID)
	if err != nil {
		h.logger.Error("saml: session create failed", "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrInternal)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		sso.KeySessionID: session.ID,
		sso.KeyStatus:    sso.StatusAuthenticated,
	})
}

// dispatch selects the SPAuthenticator for this callback. With a single SP it
// is unambiguous. With several, the RelayState carries the provider hint (the
// SP Name the original LoginURL embedded as state, optionally a richer opaque
// state whose first colon-delimited segment is the provider). An unresolvable
// hint is an error (mapped oracle-safe by the caller).
func (h *acsHandler) dispatch(relayState string) (*sp.SPAuthenticator, error) {
	if len(h.authnsByName) == 1 {
		for _, a := range h.authnsByName {
			return a, nil
		}
	}
	if a, ok := h.authnsByName[relayState]; ok {
		return a, nil
	}
	// Allow a "<provider>:<opaque-state>" relay convention so the SP hint can
	// ride alongside richer login state.
	if i := strings.IndexByte(relayState, ':'); i > 0 {
		if a, ok := h.authnsByName[relayState[:i]]; ok {
			return a, nil
		}
	}
	return nil, errors.New("saml: no SP matched relay state")
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{sso.KeyError: code})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set(sso.HeaderContentType, sso.ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
