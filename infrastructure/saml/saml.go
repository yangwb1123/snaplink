package saml

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	"github.com/yangwb1123/snaplink/platform/lifecycle/sessionhub"
	"github.com/yangwb1123/snaplink/saml/idp"
	"github.com/yangwb1123/snaplink/saml/sp"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Deps is the ROOT-module-typed dependency bundle saml.Build needs. Every
// field is a stdlib type, an sso (root-module) type, or an spi type — there is
// NO cmd/sso-server (package main) type here, because a separate module's
// package cannot import package main. The operator's forked main (which DOES
// have cmd's SAMLServerDeps) constructs a Deps from its SAMLServerDeps fields
// inside the factory closure (see the package doc for the copy-pasteable
// adaptation).
//
// Deps is the ROOT-module-typed dependency bundle saml.Build needs. It embeds
// the standard host-API bundle (interfaces/ssoext.SAMLServerDeps — the exact
// seams the stock server hands a SAML handler factory) and adds the
// SAML-specific stores. Embedding (not aliasing) keeps every existing field
// name: a fork's factory receives ssoext.SAMLServerDeps from
// ssoext.RegisterSAMLHandlers and constructs `saml.Deps{SAMLServerDeps: d, ...}`
// with no field-for-field copy — see the package doc.
type Deps struct {
	// SAMLServerDeps carries the root-module-typed seams the stock server
	// passes a registered SAML handler factory (ClientStore /
	// SessionManager / UserProvider, IssuerForClient, Issuer,
	// AuditRecorder, Logger, RegisterAuthenticator).
	ssoext.SAMLServerDeps

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

	// SessionHub OPTIONALLY wires this SAML build into the operator's
	// Cross-protocol Session Hub coordinator (platform/lifecycle/sessionhub) — pass the
	// SAME instance the core Server exposes via Server.SessionHub() (they must
	// be the same object; sessionhub.Coordinator is not itself shared any
	// other way). When set:
	//   - the SP-side ACS handler (acsHandler.serve) records BOTH a "core" and
	//     a "saml" leg for every session it creates, so Coordinator.Logout can
	//     later find and terminate it alongside every other protocol leg of
	//     the same login;
	//   - when cfg.IdP.Enabled, Build additionally calls
	//     SessionHub.SetSAMLTrigger(idpHandlers) so the coordinator can drive
	//     THIS server's IdP-initiated SLO fan-out (idp.Handlers.Fanout) to
	//     downstream SPs.
	// nil (the default) ⇒ neither behavior — byte-identical to a build
	// without this field, exactly the pre-session-hub SAML behavior.
	SessionHub *sessionhub.Coordinator
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

	// SignMetadata opts the /saml/metadata EntityDescriptor into an enveloped
	// XML-DSig (exclusive C14N, SHA-256) signed with the SAME per-tenant key the
	// IdP publishes in that document's KeyDescriptor (reusing the AssertionSigner
	// path — no new dependency), so a consumer doing automated metadata refresh
	// (Shibboleth federations, strict SPs) validates the signature with no extra
	// trust anchor. Default false ⇒ the metadata is UNSIGNED and byte-identical
	// to the historical output. An Ed25519 signing key (goxmldsig has no EdDSA
	// signature method) gracefully falls back to UNSIGNED metadata + a log,
	// never a 500.
	SignMetadata bool

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
			sessionHub:   deps.SessionHub,
			resumeOAuth:  deps.ResumeFederatedLogin,
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
			SignMetadata:      cfg.IdP.SignMetadata,
			AssertionTTL:      cfg.IdP.AssertionTTL,
			AuditRecorder:     deps.AuditRecorder,
			Logger:            logger,
			SessionIndex:      deps.SAMLSessionIndex,
			LogoutReplayStore: deps.SAMLLogoutReplayStore,
		})
		if err != nil {
			return nil, fmt.Errorf("saml: build IdP: %w", err)
		}
		// Complete the Cross-protocol Session Hub wiring loop: idpHandlers.Fanout
		// already structurally satisfies sessionhub.SAMLLogoutTrigger (same
		// method shape), so the coordinator can now drive THIS server's
		// IdP-initiated SLO fan-out. Deliberately NOT exposed via BuildResult —
		// wiring it here (rather than handing the raw *idp.Handlers to the
		// operator) is what lets Coordinator.Logout compose it without any
		// caller needing to know the SAML module exists. Nil deps.SessionHub
		// (the default) ⇒ skipped, byte-identical to a build without this field.
		if deps.SessionHub != nil {
			deps.SessionHub.SetSAMLTrigger(idpHandlers)
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
	resumeOAuth  func(http.ResponseWriter, *http.Request, string, *sso.AuthResult) bool

	// sessionHub, when non-nil (Deps.SessionHub), records this login's
	// cross-protocol global_sid: a "core" leg (the just-created session) plus
	// a "saml" leg, so a later Coordinator.Logout on that global_sid knows to
	// ALSO drive the SAML SLO fan-out for this subject. nil ⇒ no recording,
	// byte-identical to the pre-session-hub ACS handler.
	sessionHub *sessionhub.Coordinator
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
	if h.resumeOAuth != nil && h.resumeOAuth(w, r, relayState, result) {
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
	h.linkGlobalSession(r.Context(), session.ID, result.UserID)

	writeJSON(w, http.StatusOK, map[string]string{
		sso.KeySessionID: session.ID,
		sso.KeyStatus:    sso.StatusAuthenticated,
	})
}

// linkGlobalSession records the cross-protocol global_sid for a SAML SP
// login: a "core" leg (this session) plus a "saml" leg, so
// sessionhub.Coordinator.Logout later knows this login's SAML fan-out is
// "applicable". Best-effort and purely additive — a nil sessionHub (the
// default) or a LinkStore error never affects the ACS response; the session
// the caller just created is unaffected either way.
func (h *acsHandler) linkGlobalSession(ctx context.Context, sessionID, subject string) {
	if h.sessionHub == nil {
		return
	}
	gsid := sessionhub.NewGlobalSID()
	if err := h.sessionHub.Link(ctx, gsid, sessionhub.ProtocolCore, sessionID, subject); err != nil {
		h.logger.Error("saml: sessionhub link core leg failed", "error", err)
	}
	if err := h.sessionHub.Link(ctx, gsid, sessionhub.ProtocolSAML, sessionID, subject); err != nil {
		h.logger.Error("saml: sessionhub link saml leg failed", "error", err)
	}
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
