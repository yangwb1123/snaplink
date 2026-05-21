package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators/webauthn"
	webauthnsqlite "github.com/snaplink/sso/authenticators/webauthn/sqlite"
	"github.com/snaplink/sso/config"
)

// buildWebAuthnHelper assembles the helper + stores from YAML.
// Returns (nil, nil, nil, nil) when the subsystem is disabled — the
// caller skips the wiring. Returns the underlying stores so cmd can
// register their Ping method as a /readyz dependency.
func buildWebAuthnHelper(cfg config.WebAuthnConfig, logger sso.Logger) (*webauthn.Helper, webauthn.UserStore, webauthn.SessionStore, error) {
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
type webauthnDeps struct {
	Helper       *webauthn.Helper
	ClientStore  sso.ClientStore
	TokenIssuers map[string]sso.TokenIssuer
	DefaultStrat string
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
	routes := []struct {
		path    string
		handler http.HandlerFunc
	}{
		{pathWebAuthnRegistrationBegin, webauthnBeginRegistrationHandler(deps.Helper)},
		{pathWebAuthnRegistrationFinish, webauthnFinishRegistrationHandler(deps.Helper)},
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
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
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

func webauthnFinishRegistrationHandler(h *webauthn.Helper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			writeWebAuthnError(w, http.StatusBadRequest, "invalid_request", "session_id required")
			return
		}
		cred, err := h.FinishRegistration(r.Context(), sessionID, r)
		if err != nil {
			status, code := webauthnErrorStatus(err)
			writeWebAuthnError(w, status, code, err.Error())
			return
		}
		writeWebAuthnJSON(w, http.StatusOK, webauthnFinishRegistrationResponse{
			CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		})
	}
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
			return
		}
		user, cred, err := deps.Helper.FinishLogin(r.Context(), sessionID, r)
		if err != nil {
			status, code := webauthnErrorStatus(err)
			writeWebAuthnError(w, status, code, err.Error())
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
			token, err := issueWebAuthnToken(r, deps, clientID, user.Name)
			if err != nil {
				status, code := webauthnIssueErrorStatus(err)
				writeWebAuthnError(w, status, code, err.Error())
				return
			}
			resp.AccessToken = token.AccessToken
			resp.TokenType = token.TokenType
			resp.ExpiresIn = token.ExpiresIn
			resp.Scope = token.Scope
		}
		writeWebAuthnJSON(w, http.StatusOK, resp)
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

// issueWebAuthnToken builds a sso.Subject for the WebAuthn-
// authenticated user + mints an access token via the client's
// configured TokenIssuer. AMR carries "webauthn" so resource
// servers can branch on auth strength. Scopes default to the
// client's full AllowedScopes — the WebAuthn ceremony has no
// scope-selection step.
func issueWebAuthnToken(r *http.Request, deps *webauthnDeps, clientID, userID string) (*sso.Token, error) {
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
	subject := &sso.Subject{
		ID:       userID,
		Provider: "webauthn",
		ClientID: client.ID,
		AuthTime: time.Now(),
		AMR:      []string{"webauthn"},
	}
	return issuer.Issue(ctx, subject, scopes)
}

func webauthnIssueErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, errWebAuthnClientNotFound), errors.Is(err, errWebAuthnClientInactive):
		return http.StatusBadRequest, "invalid_client"
	case errors.Is(err, errWebAuthnNoIssuer):
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
