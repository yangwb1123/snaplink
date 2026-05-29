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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators/webauthn"
	webauthnsqlite "github.com/snaplink/sso/authenticators/webauthn/sqlite"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/metrics"
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
	h, err := webauthn.NewHelper(webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		SessionTTL:    cfg.SessionTTL,
	}, users, sessions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn helper: %w", err)
	}
	logger.Info("webauthn enabled",
		"rp_id", cfg.RPID,
		"origins", cfg.RPOrigins,
		"users", userDesc,
		"sessions", sessionDesc,
	)
	return h, users, sessions, nil
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

	// EncryptIDToken routes a freshly-signed id_token through the
	// server's JWE response-encryption path (fail-closed: returns
	// ("", false) when the client opted into encryption but it
	// failed, so the caller omits the id_token rather than leaking
	// cleartext). Nil-safe: nil means no encryption layer wired, so
	// the signed token passes through. Set in mountWebAuthnRoutes.
	EncryptIDToken func(ctx context.Context, client *sso.Client, signed string) (string, bool)
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
			status, code := webauthnErrorStatus(err)
			writeWebAuthnError(w, status, code, err.Error())
			recordWebAuthnRegistration(deps, "failure")
			return
		}
		writeWebAuthnJSON(w, http.StatusOK, webauthnFinishRegistrationResponse{
			CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		})
		recordWebAuthnRegistration(deps, "success")
	}
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
// servers can branch on auth strength. Scopes default to the
// client's full AllowedScopes — the WebAuthn ceremony has no
// scope-selection step.
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
	strategy := client.TokenStrategy
	if strategy == "" {
		strategy = deps.DefaultStrat
	}
	if strategy == "" {
		strategy = "jwt"
	}
	issuer, ok := deps.TokenIssuers[strategy]
	if !ok {
		return nil, fmt.Errorf("%w: %q", errWebAuthnNoIssuer, strategy)
	}
	scopes := client.AllowedScopes
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
