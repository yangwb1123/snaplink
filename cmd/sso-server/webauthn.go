package main

import "github.com/snaplink/sso/oidc"

import "github.com/snaplink/sso/spi"

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	gw "github.com/go-webauthn/webauthn/webauthn"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators/webauthn"
	webauthnsqlite "github.com/snaplink/sso/authenticators/webauthn/sqlite"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/region"
)

// buildWebAuthnHelper assembles the helper + stores from YAML.
// Returns (nil, nil, nil, nil) when the subsystem is disabled — the
// caller skips the wiring. Returns the underlying stores so cmd can
// register their Ping method as a /readyz dependency.
func buildWebAuthnHelper(cfg config.WebAuthnConfig, logger spi.Logger) (*webauthn.Helper, webauthn.UserStore, webauthn.SessionStore, error) {
	if !cfg.Enabled {
		return nil, nil, nil, nil
	}
	if cfg.RPID == "" {
		return nil, nil, nil, errors.New("webauthn.rp_id required when webauthn.enabled")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, nil, nil, errors.New("webauthn.rp_origins must list at least one origin")
	}
	users, userDesc, err := buildWebAuthnUserStore(cfg.Storage.Users)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn users: %w", err)
	}
	sessions, sessionDesc, err := buildWebAuthnSessionStore(cfg.Storage.Sessions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn sessions: %w", err)
	}
	policy, err := buildWebAuthnAttestationPolicy(cfg.Attestation)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn attestation: %w", err)
	}
	h, err := webauthn.NewHelper(webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             cfg.RPOrigins,
		SessionTTL:            cfg.SessionTTL,
		AttestationConveyance: cfg.Attestation.Conveyance,
		AttestationPolicy:     policy,
	}, users, sessions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn helper: %w", err)
	}
	logger.Info("webauthn enabled",
		"rp_id", cfg.RPID,
		"origins", cfg.RPOrigins,
		"users", userDesc,
		"sessions", sessionDesc,
		"attestation_conveyance", conveyanceLabel(cfg.Attestation.Conveyance),
		"attestation_policy", attestationPolicyLabel(policy),
	)
	return h, users, sessions, nil
}

// buildWebAuthnAttestationPolicy maps the YAML attestation block to a
// webauthn.AttestationPolicy. An empty / "off" mode yields a nil policy (no
// gating — byte-identical to a pre-policy build). A gating mode requires a
// non-empty AAGUID list; both the unknown-mode and empty-list cases fail
// loud here at boot rather than silently admitting/denying the wrong set.
func buildWebAuthnAttestationPolicy(cfg config.WebAuthnAttestationConfig) (*webauthn.AttestationPolicy, error) {
	mode := webauthn.AttestationPolicyMode(strings.ToLower(strings.TrimSpace(cfg.PolicyMode)))
	switch mode {
	case webauthn.AttestationPolicyOff, "off":
		// "off" is the operator-friendly spelling of the empty/off mode;
		// both yield a nil policy so the gate is dark.
		return nil, nil
	case webauthn.AttestationPolicyAllowlist, webauthn.AttestationPolicyDenylist:
		return webauthn.NewAttestationPolicy(mode, cfg.AAGUIDs)
	default:
		return nil, fmt.Errorf("unknown webauthn.attestation.policy_mode %q (want off|allowlist|denylist)", cfg.PolicyMode)
	}
}

// conveyanceLabel renders the configured conveyance for the startup log,
// normalizing the empty value to "none" for clarity.
func conveyanceLabel(s string) string {
	if v := strings.ToLower(strings.TrimSpace(s)); v != "" {
		return v
	}
	return "none"
}

// attestationPolicyLabel renders the policy mode for the startup log.
func attestationPolicyLabel(p *webauthn.AttestationPolicy) string {
	if !p.Enabled() {
		return "off"
	}
	return string(p.Mode)
}

func buildWebAuthnUserStore(cfg config.WebAuthnBackendConfig) (webauthn.UserStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return webauthn.NewMemoryUserStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("webauthn.storage.users.sqlite.dsn required when backend=sqlite")
		}
		store, err := webauthnsqlite.NewUserStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown webauthn.storage.users.backend %q", cfg.Backend)
	}
}

func buildWebAuthnSessionStore(cfg config.WebAuthnBackendConfig) (webauthn.SessionStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return webauthn.NewMemorySessionStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("webauthn.storage.sessions.sqlite.dsn required when backend=sqlite")
		}
		store, err := webauthnsqlite.NewSessionStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown webauthn.storage.sessions.backend %q", cfg.Backend)
	}
}

// WebAuthn ceremony endpoint paths. Public so embedders writing
// docs / client code can reference them.
const (
	pathWebAuthnRegistrationBegin  = "/webauthn/registration/begin"
	pathWebAuthnRegistrationFinish = "/webauthn/registration/finish"
	pathWebAuthnLoginBegin         = "/webauthn/login/begin"
	pathWebAuthnLoginFinish        = "/webauthn/login/finish"
)

// webauthnDeps bundles everything the ceremony handlers need.
// Helper drives the WebAuthn protocol; ClientStore + TokenIssuers
// are optional — when supplied, /webauthn/login/finish accepts a
// `client_id` query parameter and issues a token for the
// authenticated user against that client (turning WebAuthn into a
// real first-class login method instead of just credential
// verification).
//
// oauth.RefreshTokenStore + oidc.IDTokenIssuer are independently optional. When
// the resolved client's AllowedScopes contains `offline_access`
// AND a oauth.RefreshTokenStore is wired, the response carries a
// refresh_token. When the scopes contain `openid` AND an
// oidc.IDTokenIssuer is wired, the response carries an id_token. Either
// missing dep silently degrades to the next-lower disclosure (just
// like /auth/login when those backends aren't configured).
type webauthnDeps struct {
	Helper            *webauthn.Helper
	ClientStore       sso.ClientStore
	TokenIssuers      map[string]sso.TokenIssuer
	DefaultStrat      string
	RefreshTokenStore oauth.RefreshTokenStore
	RefreshTokenTTL   time.Duration
	IDTokenIssuer     oidc.IDTokenIssuer
	Metrics           *metrics.Metrics // nil-safe; emit only when present

	// AuditRecorder records the WebAuthn registration audit events:
	// webauthn_registered (success, carrying the AAGUID for operator
	// allowlist curation) and webauthn_attestation_denied (failure, when
	// the attestation policy rejects an authenticator). Nil-safe — when
	// unset (an embedder without an audit pipeline, or a pre-audit build)
	// no registration audit event is emitted, leaving the begin/finish
	// flow byte-identical to before. Set in main from a.recorder.
	AuditRecorder *audit.Recorder

	// IDTokenIssuerForClient selects the per-tenant id_token issuer so a
	// WebAuthn-minted id_token is signed with the same key as that
	// tenant's access + id tokens elsewhere (closing the last surface
	// that bypassed WithTenantTokenIssuer). Mirrors the server's
	// fail-closed selector: err != nil ⇒ a misconfigured/unregistered
	// tenant issuer; emit=false ⇒ the tenant strategy can't mint
	// id_tokens (omit, never sign with the shared key). Nil-safe: when
	// unset (embedders constructing webauthnDeps directly) the handler
	// falls back to IDTokenIssuer for byte-identical legacy behavior.
	// Set in mountWebAuthnRoutes from *sso.Server.
	IDTokenIssuerForClient func(c *sso.Client) (oidc.IDTokenIssuer, bool, error)

	// IssuerForClient selects the per-tenant ACCESS-token issuer so a
	// WebAuthn-minted access token is signed with the same key as that
	// tenant's tokens from /auth/login + /token + its WebAuthn id_token —
	// the symmetric finish to IDTokenIssuerForClient (without it a tenant
	// client's WebAuthn access token could land on a different key than its
	// id_token). Mirrors the server's resolution order (tenant → client
	// strategy → default) and fail-closed error. Nil-safe: when unset
	// (embedders constructing webauthnDeps directly) the handler falls back
	// to the TokenStrategy lookup below for byte-identical legacy behavior.
	// Set in mountWebAuthnRoutes from *sso.Server.
	IssuerForClient func(c *sso.Client) (string, sso.TokenIssuer, error)

	// EncryptIDToken routes a freshly-signed id_token through the
	// server's JWE response-encryption path (fail-closed: returns
	// ("", false) when the client opted into encryption but it
	// failed, so the caller omits the id_token rather than leaking
	// cleartext). Nil-safe: nil means no encryption layer wired, so
	// the signed token passes through. Set in mountWebAuthnRoutes.
	EncryptIDToken func(ctx context.Context, client *sso.Client, signed string) (string, bool)

	// RegionResolver + ResidencyDecision close the data-residency hole on the
	// WebAuthn LOGIN mint path. WebAuthn login mints tokens exactly like
	// /auth/login, but the ceremony is mounted as RAW http.HandlerFunc (no
	// core.HandlerContext), so the in-pipeline login residency gate
	// (residencyGateLogin, which reads the serving region the region
	// middleware stashes on the HandlerContext) never runs here. Without these
	// a region-constrained tenant's user could complete WebAuthn login from a
	// disallowed serving region and receive tokens, bypassing residency.
	//
	// RegionResolver resolves the serving region from the raw *http.Request
	// (the same resolver the region middleware uses); ResidencyDecision is the
	// server's context-free residency seam (*sso.Server.ResidencyDecision),
	// returning (wireCode, denied) for a tenant + serving region. Set in cmd
	// ONLY when a region resolver is configured. BOTH nil (the embedder /
	// no-region default) ⇒ NO residency check ⇒ byte-identical to a
	// pre-residency build (residency simply isn't enforced for WebAuthn).
	RegionResolver    region.Resolver
	ResidencyDecision func(ctx context.Context, tenantID string, servingRegion region.ID, isWrite bool) (string, bool)
}

// mountWebAuthnRoutes registers the four ceremony endpoints on the
// SSO router. Begin endpoints accept JSON {"username", "display_name"};
// Finish endpoints take session_id from the ?session_id= query
// parameter and the WebAuthn attestation/assertion response in the
// body (passed through to go-webauthn unchanged).
//
// All four endpoints return JSON. Failure shape mirrors the OAuth
// error envelope ({"error", "error_description"}) so client-side
// integration is consistent across SSO surfaces.
func mountWebAuthnRoutes(srv *sso.Server, deps *webauthnDeps) error {
	if deps == nil || deps.Helper == nil {
		return nil
	}
	// Select the per-tenant id_token issuer so a tenant's WebAuthn
	// id_token is signed by the tenant's key (same fail-closed selector
	// /auth/login + /token use), then route the signed token through the
	// server's response encryption (fail-closed for encryption-opted-in
	// clients) — so /webauthn/login/finish matches /auth/login's contract.
	deps.IssuerForClient = srv.IssuerForClient
	deps.IDTokenIssuerForClient = srv.IDTokenIssuerForClient
	deps.EncryptIDToken = srv.EncryptIDTokenForClient
	routes := []struct {
		path    string
		handler http.HandlerFunc
	}{
		{pathWebAuthnRegistrationBegin, webauthnBeginRegistrationHandler(deps.Helper)},
		{pathWebAuthnRegistrationFinish, webauthnFinishRegistrationHandler(deps)},
		{pathWebAuthnLoginBegin, webauthnBeginLoginHandler(deps.Helper)},
		{pathWebAuthnLoginFinish, webauthnFinishLoginHandler(deps)},
	}
	for _, r := range routes {
		if err := srv.Handle(http.MethodPost, r.path, r.handler); err != nil {
			return fmt.Errorf("mount %s: %w", r.path, err)
		}
	}
	return nil
}

type webauthnBeginRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type webauthnBeginRegistrationResponse struct {
	SessionID string          `json:"session_id"`
	Options   json.RawMessage `json:"options"`
}

type webauthnBeginLoginResponse struct {
	SessionID string          `json:"session_id"`
	Options   json.RawMessage `json:"options"`
}

type webauthnFinishRegistrationResponse struct {
	CredentialID string `json:"credential_id"`
}

type webauthnFinishLoginResponse struct {
	Username     string `json:"username"`
	CredentialID string `json:"credential_id"`

	// Token-issuance fields — populated only when ?client_id= is
	// supplied AND the cmd has a ClientStore + TokenIssuer wired.
	// Without client_id the handler stays in v1 credential-
	// verification mode so embedders that integrate their own token
	// path aren't disturbed.
	//
	// oauth.RefreshToken populates only when the client's AllowedScopes
	// contains `offline_access` AND a oauth.RefreshTokenStore is wired.
	// IDToken populates only when the AllowedScopes contains `openid`
	// AND an oidc.IDTokenIssuer is wired. Either dep missing leaves the
	// field empty (omitted from the JSON).
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

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
func recordWebAuthnRegistered(deps *webauthnDeps, r *http.Request, cred *gw.Credential) {
	if deps == nil || deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:      audit.EventWebAuthnRegistered,
		Outcome:   audit.OutcomeSuccess,
		Provider:  "webauthn",
		ActorIP:   audit.ClientIP(r),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now().UTC(),
	}
	audit.SetMeta(e, "aaguid", webauthn.CredentialAAGUID(cred.Authenticator.AAGUID))
	deps.AuditRecorder.Record(r.Context(), e)
}

// recordWebAuthnAttestationDenied emits the failure audit event for an
// attestation-policy rejection, carrying the rejected AAGUID + the gating
// mode + the operator-side reason. Nil-safe when no recorder is wired.
func recordWebAuthnAttestationDenied(deps *webauthnDeps, r *http.Request, denied *webauthn.AttestationDeniedError) {
	if deps == nil || deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:      audit.EventWebAuthnAttestationDenied,
		Outcome:   audit.OutcomeFailure,
		Provider:  "webauthn",
		ActorIP:   audit.ClientIP(r),
		UserAgent: r.UserAgent(),
		Reason:    denied.Error(),
		Timestamp: time.Now().UTC(),
	}
	audit.SetMeta(e, "aaguid", denied.AAGUID)
	audit.SetMeta(e, "policy_mode", string(denied.Mode))
	deps.AuditRecorder.Record(r.Context(), e)
}

// recordWebAuthnRegistration increments the registration counter
// for the given outcome. Nil-safe: when metrics are disabled
// (deps.Metrics nil), emit is silently skipped.
func recordWebAuthnRegistration(deps *webauthnDeps, outcome string) {
	if deps == nil || deps.Metrics == nil {
		return
	}
	deps.Metrics.WebAuthnRegistrationsTotal.WithLabelValues(outcome).Inc()
}

// recordWebAuthnAssertion mirrors recordWebAuthnRegistration for the
// login-finish path.
func recordWebAuthnAssertion(deps *webauthnDeps, outcome string) {
	if deps == nil || deps.Metrics == nil {
		return
	}
	deps.Metrics.WebAuthnAssertionsTotal.WithLabelValues(outcome).Inc()
}

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
			result, err := issueWebAuthnToken(r, deps, clientID, user.Name)
			if err != nil {
				status, code := webauthnIssueErrorStatus(err)
				writeWebAuthnError(w, status, code, err.Error())
				// Token issuance failure post-assertion is still a
				// crypto-verified user — the assertion succeeded. We
				// label the issuance failure separately via the
				// existing http_requests_total status_class signal.
				// Don't double-count by also flagging this as an
				// assertion failure.
				recordWebAuthnAssertion(deps, "success")
				return
			}
			resp.AccessToken = result.AccessToken
			resp.TokenType = result.TokenType
			resp.ExpiresIn = result.ExpiresIn
			resp.Scope = result.Scope
			resp.RefreshToken = result.RefreshToken
			resp.IDToken = result.IDToken
		}
		writeWebAuthnJSON(w, http.StatusOK, resp)
		recordWebAuthnAssertion(deps, "success")
	}
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

func (e *webauthnResidencyError) Error() string {
	return fmt.Sprintf("webauthn: residency denied: %s", e.code)
}
func (e *webauthnResidencyError) Unwrap() error { return errWebAuthnResidency }

// webauthnIssueResult is the projection of every issuance the
// /webauthn/login/finish handler can emit. Bringing access /
// refresh / id together keeps the handler response shape stable
// while letting the issuer logic branch on what's wired.
type webauthnIssueResult struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	Scope        string
	RefreshToken string
	IDToken      string
}

// idTokenIssuerForWebAuthn resolves the id_token issuer that should mint
// this client's WebAuthn id_token, returning (issuer, emit, err) with the
// same fail-closed contract the server's selector uses.
//
// When mounted via mountWebAuthnRoutes, deps.IDTokenIssuerForClient is the
// server's per-tenant selector, so a tenant's id_token is signed by the
// tenant's key (an unregistered tenant issuer errors; an opaque/non-OIDC
// tenant strategy yields emit=false → the caller omits, never the shared
// key). When that closure is unset — an embedder constructing webauthnDeps
// directly without the server seam — fall back to the shared
// deps.IDTokenIssuer for byte-identical legacy behavior (emit tracks
// whether one is wired).
func idTokenIssuerForWebAuthn(deps *webauthnDeps, client *sso.Client) (oidc.IDTokenIssuer, bool, error) {
	if deps.IDTokenIssuerForClient != nil {
		return deps.IDTokenIssuerForClient(client)
	}
	return deps.IDTokenIssuer, deps.IDTokenIssuer != nil, nil
}

// issueWebAuthnToken builds a sso.Subject for the WebAuthn-
// authenticated user + mints an access token via the client's
// configured TokenIssuer. AMR carries "webauthn" so resource
// servers can branch on auth strength. The WebAuthn ceremony has no
// scope-selection step, so it requests the client's full AllowedScopes
// through the shared oauth.GrantedScopes gate (the same scope-
// authorization seam as /auth/login + /token) — a full-allowance request
// never narrows or errors, but routing it through the gate keeps EVERY
// token-minting path on one seam rather than special-casing WebAuthn.
//
// When the client's scopes include `offline_access` AND deps.
// oauth.RefreshTokenStore is wired, a refresh_token rides along; when
// `openid` is in scope AND an id_token issuer resolves for the client
// (per-tenant via idTokenIssuerForWebAuthn), an id_token does. Either
// dep missing degrades silently — same shape /auth/login uses when the
// corresponding backend isn't configured.
func issueWebAuthnToken(r *http.Request, deps *webauthnDeps, clientID, userID string) (*webauthnIssueResult, error) {
	ctx := r.Context()
	client, err := deps.ClientStore.Get(ctx, clientID)
	if err != nil {
		return nil, errWebAuthnClientNotFound
	}
	if !client.Active {
		return nil, errWebAuthnClientInactive
	}
	// Data-residency write-gate. Reached ONLY post-assertion (the caller
	// invokes issueWebAuthnToken after deps.Helper.FinishLogin verified the
	// WebAuthn assertion — the user is authenticated), and now that the client
	// is resolved its TenantID is known, so this mirrors residencyGateLogin
	// EXACTLY: gate the MINT (isWrite=true) on the tenant's ResidencyPolicy.
	// Both hooks must be wired (cmd sets them only when a region resolver is
	// configured) — either nil ⇒ no check ⇒ byte-identical pre-residency
	// behavior. FAIL-OPEN consistent with the region middleware's nonfatal
	// contract: a resolver error yields an empty serving region, which
	// ResidencyDecision (via checkTenantResidency) treats as unconstrained.
	if deps.RegionResolver != nil && deps.ResidencyDecision != nil {
		sr, _ := deps.RegionResolver.Resolve(r)
		if code, denied := deps.ResidencyDecision(ctx, client.TenantID, sr, true); denied {
			return nil, &webauthnResidencyError{code: code}
		}
	}
	// Prefer the server's tenant-aware selector (tenant → client strategy →
	// default) so a tenant client's WebAuthn access token is signed with the
	// same key as its id_token + its tokens from /auth/login + /token. When
	// the hook is unset (embedders constructing webauthnDeps directly) fall
	// back to the per-client strategy lookup for byte-identical legacy behavior.
	var issuer sso.TokenIssuer
	if deps.IssuerForClient != nil {
		var ierr error
		if _, issuer, ierr = deps.IssuerForClient(client); ierr != nil {
			return nil, fmt.Errorf("%w: %v", errWebAuthnNoIssuer, ierr)
		}
	} else {
		strategy := client.TokenStrategy
		if strategy == "" {
			strategy = deps.DefaultStrat
		}
		if strategy == "" {
			strategy = "jwt"
		}
		var ok bool
		if issuer, ok = deps.TokenIssuers[strategy]; !ok {
			return nil, fmt.Errorf("%w: %q", errWebAuthnNoIssuer, strategy)
		}
	}
	scopes, err := oauth.GrantedScopes(client.AllowedScopes, client)
	if err != nil {
		// Unreachable for a full-allowance request (every scope is in the
		// allowlist; openid is always permitted), but handled for parity
		// with the device/CIBA callers so WebAuthn can never silently skip
		// the gate if GrantedScopes' contract changes.
		return nil, fmt.Errorf("webauthn: scope authorization: %w", err)
	}
	authTime := time.Now()
	subject := &sso.Subject{
		ID:       userID,
		Provider: "webauthn",
		ClientID: client.ID,
		AuthTime: authTime,
		AMR:      []string{"webauthn"},
	}
	token, err := issuer.Issue(ctx, subject, scopes)
	if err != nil {
		return nil, fmt.Errorf("webauthn: issue access token: %w", err)
	}
	result := &webauthnIssueResult{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresIn:   token.ExpiresIn,
		Scope:       token.Scope,
	}
	// id_token: gated on openid scope AND a resolvable id_token issuer.
	// Mirrors the contract /auth/login implements — clients that request
	// openid get an id_token; clients that don't, don't. The issuer is
	// resolved PER-TENANT so a tenant's WebAuthn id_token is signed by
	// the tenant's key (same key as its access + id tokens elsewhere),
	// not the shared key.
	if slices.Contains(scopes, sso.ScopeOpenID) {
		idIssuer, emit, resErr := idTokenIssuerForWebAuthn(deps, client)
		if resErr != nil {
			// Misconfigured/unregistered tenant issuer: fail closed
			// (errWebAuthnIDToken → 500), exactly as the access-token
			// path 500s on an unregistered strategy. Never sign this
			// tenant's id_token with the shared key.
			return nil, fmt.Errorf("%w: %v", errWebAuthnIDToken, resErr)
		}
		// emit=false ⇒ no id_token issuer wired, OR the tenant's strategy
		// can't mint id_tokens (e.g. opaque session tokens). Omit the
		// id_token rather than sign with the shared key — same silent
		// degrade /auth/login uses when no issuer is configured. Flow
		// continues to the refresh-token block below regardless.
		if emit {
			idToken, err := idIssuer.IssueIDToken(ctx, &oidc.IDTokenRequest{
				Subject:  userID,
				Audience: client.ID,
				AuthTime: authTime,
				AMR:      []string{"webauthn"},
			})
			if err != nil {
				return nil, fmt.Errorf("%w: %v", errWebAuthnIDToken, err)
			}
			// Fail-closed encryption: a client that registered
			// id_token_encrypted_response_alg gets a JWE; if encryption
			// is requested but fails, omit the id_token (no cleartext
			// leak) rather than returning the signed form.
			if deps.EncryptIDToken != nil {
				if enc, ok := deps.EncryptIDToken(ctx, client, idToken); ok {
					result.IDToken = enc
				}
			} else {
				result.IDToken = idToken
			}
		}
	}
	// refresh_token: gated on a wired oauth.RefreshTokenStore — matches
	// /auth/login + /token authorization_code which both issue
	// unconditionally when the store is present (RFC 6749 leaves it
	// to AS discretion; the SDK's contract is "wired → emit"). Same
	// shape /token grant=authorization_code produces, so existing
	// refresh-token rotation handlers work against a WebAuthn-issued
	// token unchanged.
	if deps.RefreshTokenStore != nil {
		refresh, err := mintWebAuthnRefreshToken(ctx, deps, client, userID, scopes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errWebAuthnRefreshToken, err)
		}
		result.RefreshToken = refresh
	}
	return result, nil
}

// mintWebAuthnRefreshToken generates a cryptographically random
// refresh token + persists it. TTL preference: per-client override
// > deps.RefreshTokenTTL > sso.DefaultRefreshTokenTTL.
func mintWebAuthnRefreshToken(ctx context.Context, deps *webauthnDeps, client *sso.Client, userID string, scopes []string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	ttl := client.RefreshTokenTTL
	if ttl <= 0 {
		ttl = deps.RefreshTokenTTL
	}
	if ttl <= 0 {
		ttl = sso.DefaultRefreshTokenTTL
	}
	familyBuf := make([]byte, 32)
	if _, err := rand.Read(familyBuf); err != nil {
		return "", fmt.Errorf("random family id: %w", err)
	}
	now := time.Now()
	entry := &oauth.RefreshToken{
		UserID:    userID,
		ClientID:  client.ID,
		Provider:  "webauthn",
		Scopes:    append([]string(nil), scopes...),
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		FamilyID:  base64.RawURLEncoding.EncodeToString(familyBuf),
	}
	if err := deps.RefreshTokenStore.Issue(ctx, token, entry); err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	return token, nil
}

func webauthnIssueErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, errWebAuthnClientNotFound), errors.Is(err, errWebAuthnClientInactive):
		return http.StatusBadRequest, "invalid_client"
	case errors.Is(err, errWebAuthnResidency):
		// Residency denial: 403 + the engine's DYNAMIC governance code
		// (region_not_allowed / residency_violation), carried on the typed
		// error so the two distinct codes aren't collapsed — same disposition
		// residencyGateLogin gives the in-pipeline login path. Defensive
		// fallback to access_denied if the typed wrapper isn't present.
		var re *webauthnResidencyError
		if errors.As(err, &re) && re.code != "" {
			return http.StatusForbidden, re.code
		}
		return http.StatusForbidden, sso.ErrAccessDenied
	case errors.Is(err, errWebAuthnNoIssuer),
		errors.Is(err, errWebAuthnIDToken),
		errors.Is(err, errWebAuthnRefreshToken):
		return http.StatusInternalServerError, "server_error"
	default:
		return http.StatusInternalServerError, "server_error"
	}
}

func decodeBeginRequest(r *http.Request) (*webauthnBeginRequest, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	var req webauthnBeginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return &req, nil
}

// webauthnErrorStatus maps known sentinels to HTTP status + error code.
// Unknown sessions and unknown users both return 404 so a probe can't
// distinguish "wrong session_id" from "never enrolled" — same oracle-
// leak resistance the OAuth code paths follow.
func webauthnErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, webauthn.ErrSessionUnknown), errors.Is(err, webauthn.ErrSessionExpired):
		return http.StatusNotFound, "session_invalid"
	case errors.Is(err, webauthn.ErrUserUnknown):
		return http.StatusNotFound, "session_invalid"
	default:
		return http.StatusBadRequest, "ceremony_failed"
	}
}

func writeWebAuthnJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeWebAuthnError(w http.ResponseWriter, status int, code, description string) {
	writeWebAuthnJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}
