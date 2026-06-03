package saml

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/saml/idp"
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
	// (tenant -> client strategy -> default). The SP side does NOT use it (it
	// returns a session id). The IdP side REQUIRES it: it resolves the SP
	// client's per-tenant signing key through this path (then borrows the key
	// via the issuer's CryptoSigner() seam) so an assertion is signed with the
	// SAME key published in that tenant's metadata. REQUIRED when IdP is
	// enabled; may be nil for an SP-only build.
	IssuerForClient func(c *sso.Client) (string, sso.TokenIssuer, error)

	// Issuer is the configured AS issuer URL. REQUIRED when IdP is enabled (the
	// IdP entity id is Issuer + "/saml", stamped into every assertion Issuer +
	// the published metadata). Unused by the session-only SP ACS.
	Issuer string

	// AuditRecorder is the shared audit pipeline. The IdP records a
	// login_success (provider "saml-idp") on it per issued assertion. Nil ⇒ the
	// IdP issues without an audit event (the SP side never used it).
	AuditRecorder *audit.Recorder

	// Logger is the server logger. Nil ⇒ a no-op logger is used.
	Logger spi.Logger

	// SAMLSessionIndex enables the IdP-side SLO back-channel FAN-OUT (global
	// single logout): it records, per subject, the SAML SPs that subject has an
	// active SSO session with at assertion-issuance, and an SP-initiated /saml/slo
	// then pushes a SIGNED LogoutRequest to every OTHER such SP's registered SLO
	// URL (async + best-effort + bounded, the SAML analogue of OIDC back-channel
	// logout). OPTIONAL: nil ⇒ the fan-out is DISABLED and the single-SP SLO
	// behavior is byte-identical (nothing recorded or read). Wire
	// idp.NewMemorySessionIndex(0, 0) for the default bounded in-memory index, or
	// a shared sqlite/redis SAMLSessionIndex for a multi-replica IdP. IdP-only;
	// the SP side does not use it.
	SAMLSessionIndex idp.SAMLSessionIndex

	// SAMLLogoutReplayStore OPTIONALLY overrides the IdP's per-replica in-memory
	// LogoutRequest-ID replay-dedup cache with a SHARED idp.LogoutReplayStore (the
	// sqlite peer in saml/idp/sqlite) so a multi-replica IdP catches a captured,
	// validly-signed LogoutRequest replayed to a DIFFERENT replica. OPTIONAL: nil
	// ⇒ the bounded in-memory default (byte-identical). IdP-only. (The SP-side
	// replay stores are wired per-SP on sp.SPConfig.AssertionReplayStore /
	// LogoutReplayStore, since each upstream IdP federation has its own.)
	SAMLLogoutReplayStore idp.LogoutReplayStore
}

// Config wraps the per-IdP SP configs the operator wants to wire. One SPConfig
// yields one SPAuthenticator; the ACS handler dispatches a POSTed assertion to
// the right authenticator by a provider hint in RelayState (or the single SP
// when only one is configured).
//
// IdP holds the IdP-side (this server ISSUES assertions to downstream SPs)
// config. When IdP.Enabled is false (the default), Build produces ONLY the SP
// side — byte-identical to the Phase B behavior. SP-CLIENT registration for the
// IdP lives in sso.Client.Attributes (the idp.Attr* keys), NOT here — the IdP
// reads the registered client store at request time:
//
//	saml_sp_entity_id           — the SP's SAML entity id (AuthnRequest Issuer)
//	saml_sp_acs_urls            — pipe-delimited registered ACS allowlist
//	saml_sp_signing_cert        — PEM cert verifying a signed AuthnRequest AND a
//	                              SP-initiated LogoutRequest (SLO, MANDATORY there)
//	saml_sp_require_signed_request — "true" to require a signed AuthnRequest
//	saml_sp_nameid_format       — per-SP NameID format override
//	saml_sp_slo_url             — pipe-delimited registered SLO allowlist; the
//	                              LogoutResponse goes ONLY here (https; like ACS)
//	saml_sp_slo_binding         — back-channel fan-out WIRE binding: redirect|post
//	                              (default redirect)
//	saml_sp_slo_channel         — SLO mode: backchannel (default; direct
//	                              server-to-server fan-out) | frontchannel (the
//	                              browser-redirect SLO chain via /saml/slo/continue,
//	                              for SPs not reachable from the IdP)
type Config struct {
	SPs []sp.SPConfig
	IdP IdPConfig
}

// IdPConfig is the IdP-side configuration. The SP-client config (entity id, ACS
// allowlist, signing cert) is per-client and lives on sso.Client.Attributes;
// this struct holds only the IdP-wide knobs.
type IdPConfig struct {
	// Enabled gates the IdP handlers (/saml/metadata, /saml/sso,
	// /saml/sso/finish, the SP-initiated /saml/slo Single Logout receiver, and the
	// front-channel chain resume endpoint /saml/slo/continue). False ⇒ Build
	// appends NO IdP handlers (SP-only, byte-identical to Phase B).
	Enabled bool

	// MetadataTTL is the Cache-Control max-age on /saml/metadata. <=0 ⇒ 1h.
	MetadataTTL time.Duration

	// AssertionTTL is the minted-assertion validity window. <=0 ⇒ 5m.
	AssertionTTL time.Duration

	// LoginPath is where /saml/sso redirects to authenticate. Empty ⇒
	// "/auth/login".
	LoginPath string

	// SSOURL is the absolute public URL of /saml/sso, published in metadata.
	// Empty ⇒ Issuer + "/saml/sso".
	SSOURL string
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

// Build constructs the SP side (an SPAuthenticator per SPConfig + the
// POST /auth/saml/callback ACS handler) and, when cfg.IdP.Enabled, the IdP side
// (the three /saml/{metadata,sso,sso/finish} handlers that ISSUE signed
// assertions to downstream SPs), returning them as importable root-typed
// results for the operator to wire. A construction error (bad SP config,
// unresolved IdP trust anchor, missing required dep) fails the operator's boot
// closed.
//
// At least one side MUST be requested: either ≥1 SP config, or IdP enabled.
func Build(deps Deps, cfg Config) (*BuildResult, error) {
	if deps.SessionManager == nil {
		return nil, errors.New("saml: SessionManager required (the SP ACS creates the session; the IdP validates it)")
	}
	if deps.UserProvider == nil {
		return nil, errors.New("saml: UserProvider required (the SP ACS upserts the user; the IdP reads it)")
	}
	if len(cfg.SPs) == 0 && !cfg.IdP.Enabled {
		return nil, errors.New("saml: nothing to build — set at least one SP config or enable the IdP")
	}

	logger := deps.Logger
	if logger == nil {
		logger = spi.NopLogger{}
	}

	handlers := make([]HandlerSpec, 0, 4)

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

	// SP-side ACS handler is mounted whenever any SP is configured.
	if len(cfg.SPs) > 0 {
		acs := &acsHandler{
			authnsByName: authnsByName,
			sessions:     deps.SessionManager,
			users:        deps.UserProvider,
			logger:       logger,
		}
		handlers = append(handlers, HandlerSpec{
			Method:  http.MethodPost,
			Path:    sso.PathSAMLSSOCallback, // "/auth/saml/callback"
			Handler: acs.serve,
		})

		// SP-side SLO handler: the UPSTREAM IdP redirects/POSTs a signed
		// LogoutRequest here to log this server out. Mounted (GET+POST, both SLO
		// bindings) whenever any SP is configured — an SP that hasn't set an SP
		// signing key simply can't acknowledge (it still terminates locally).
		slo := &sloSPHandler{
			authnsByName: authnsByName,
			sessions:     deps.SessionManager,
			logger:       logger,
		}
		handlers = append(handlers,
			HandlerSpec{Method: http.MethodGet, Path: sso.PathSAMLSPSLO, Handler: slo.serve},
			HandlerSpec{Method: http.MethodPost, Path: sso.PathSAMLSPSLO, Handler: slo.serve},
		)
	}

	// IdP side: append the three issuing handlers when enabled.
	if cfg.IdP.Enabled {
		idpHandlers, err := idp.NewHandlers(idp.Deps{
			ClientStore:       deps.ClientStore,
			SessionManager:    deps.SessionManager,
			UserProvider:      deps.UserProvider,
			IssuerForClient:   deps.IssuerForClient,
			Issuer:            deps.Issuer,
			LoginPath:         cfg.IdP.LoginPath,
			SSOURL:            cfg.IdP.SSOURL,
			MetadataTTL:       cfg.IdP.MetadataTTL,
			AssertionTTL:      cfg.IdP.AssertionTTL,
			AuditRecorder:     deps.AuditRecorder,
			Logger:            logger,
			SessionIndex:      deps.SAMLSessionIndex,
			LogoutReplayStore: deps.SAMLLogoutReplayStore,
		})
		if err != nil {
			return nil, fmt.Errorf("saml: build IdP: %w", err)
		}
		handlers = append(handlers,
			HandlerSpec{Method: http.MethodGet, Path: sso.PathSAMLMetadata, Handler: idpHandlers.Metadata},
			// /saml/sso accepts both bindings: HTTP-Redirect (GET) +
			// HTTP-POST (POST) AuthnRequests.
			HandlerSpec{Method: http.MethodGet, Path: sso.PathSAMLSSO, Handler: idpHandlers.SSO},
			HandlerSpec{Method: http.MethodPost, Path: sso.PathSAMLSSO, Handler: idpHandlers.SSO},
			HandlerSpec{Method: http.MethodPost, Path: sso.PathSAMLSSO + "/finish", Handler: idpHandlers.Finish},
			// /saml/slo accepts both SLO bindings: HTTP-Redirect (GET) +
			// HTTP-POST (POST) SP-initiated LogoutRequests.
			HandlerSpec{Method: http.MethodGet, Path: sso.PathSAMLSLO, Handler: idpHandlers.SLO},
			HandlerSpec{Method: http.MethodPost, Path: sso.PathSAMLSLO, Handler: idpHandlers.SLO},
			// /saml/slo/continue resumes the FRONT-channel browser-redirect SLO
			// chain: each front-channel SP redirects the browser HERE with a signed
			// LogoutResponse after terminating its local session (GET only — the
			// front-channel binding is HTTP-Redirect).
			HandlerSpec{Method: http.MethodGet, Path: sso.PathSAMLSLOContinue, Handler: idpHandlers.SLOContinue},
		)
	}

	return &BuildResult{
		Authenticators: authns,
		Handlers:       handlers,
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
