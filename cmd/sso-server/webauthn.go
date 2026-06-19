package main

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
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators/webauthn"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
)

// buildWebAuthnHelper assembles the helper + stores from YAML.
// Returns (nil, nil, nil, nil) when the subsystem is disabled — the
// caller skips the wiring. Returns the underlying stores so cmd can
// register their Ping method as a /readyz dependency.

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
	if err := webAuthnResidencyGate(r, deps, client); err != nil {
		return nil, err
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
	token, result, err := issueWebAuthnAccessToken(ctx, deps, client, userID, authTime, scopes)
	if err != nil {
		return nil, err
	}
	if slices.Contains(scopes, sso.ScopeOpenID) {
		idToken, err := issueWebAuthnIDToken(ctx, deps, client, userID, authTime, token.AccessToken)
		if err != nil {
			return nil, err
		}
		result.IDToken = idToken
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

// issueWebAuthnAccessToken resolves the per-tenant access-token issuer, builds
// the WebAuthn subject (AMR carries "webauthn" so resource servers can branch on
// auth strength), and mints the access token. Returns both the raw token (its
// AccessToken seeds the id_token's at_hash) and the seeded result projection.
func issueWebAuthnAccessToken(ctx context.Context, deps *webauthnDeps, client *sso.Client, userID string, authTime time.Time, scopes []string) (*sso.Token, *webauthnIssueResult, error) {
	issuer, err := resolveWebAuthnIssuer(deps, client)
	if err != nil {
		return nil, nil, err
	}
	subject := &sso.Subject{
		ID:       userID,
		Provider: "webauthn",
		ClientID: client.ID,
		AuthTime: authTime,
		AMR:      []string{"webauthn"},
	}
	token, err := issuer.Issue(ctx, subject, scopes)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: issue access token: %w", err)
	}
	return token, &webauthnIssueResult{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresIn:   token.ExpiresIn,
		Scope:       token.Scope,
	}, nil
}

// webAuthnResidencyGate applies the data-residency write-gate. Reached ONLY
// post-assertion (the caller invokes issueWebAuthnToken after FinishLogin
// verified the assertion — the user is authenticated), and now that the client
// is resolved its TenantID is known, so this mirrors residencyGateLogin EXACTLY:
// gate the MINT (isWrite=true) on the tenant's ResidencyPolicy. Both hooks must
// be wired (cmd sets them only when a region resolver is configured) — either
// nil ⇒ no check ⇒ byte-identical pre-residency behavior. FAIL-OPEN consistent
// with the region middleware's nonfatal contract: a resolver error yields an
// empty serving region, which ResidencyDecision treats as unconstrained.
func webAuthnResidencyGate(r *http.Request, deps *webauthnDeps, client *sso.Client) error {
	if deps.RegionResolver == nil || deps.ResidencyDecision == nil {
		return nil
	}
	sr, _ := deps.RegionResolver.Resolve(r)
	if code, denied := deps.ResidencyDecision(r.Context(), client.TenantID, sr, true); denied {
		return &webauthnResidencyError{code: code}
	}
	return nil
}

// resolveWebAuthnIssuer selects the access-token issuer. Prefer the server's
// tenant-aware selector (tenant → client strategy → default) so a tenant
// client's WebAuthn access token is signed with the same key as its id_token +
// its tokens from /auth/login + /token. When the hook is unset (embedders
// constructing webauthnDeps directly) fall back to the per-client strategy
// lookup for byte-identical legacy behavior.
func resolveWebAuthnIssuer(deps *webauthnDeps, client *sso.Client) (sso.TokenIssuer, error) {
	if deps.IssuerForClient != nil {
		_, issuer, ierr := deps.IssuerForClient(client)
		if ierr != nil {
			return nil, fmt.Errorf("%w: %v", errWebAuthnNoIssuer, ierr)
		}
		return issuer, nil
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
	return issuer, nil
}

// issueWebAuthnIDToken mints the id_token for an openid-scoped WebAuthn login.
// Returns ("", nil) when no id_token should be emitted (no issuer wired, or the
// tenant's strategy can't mint id_tokens) — the same silent degrade /auth/login
// uses. The issuer is resolved PER-TENANT so a tenant's id_token is signed by
// the tenant's key (same key as its access + id tokens elsewhere), not the
// shared key; a misconfigured/unregistered tenant issuer fails closed (500).
func issueWebAuthnIDToken(ctx context.Context, deps *webauthnDeps, client *sso.Client, userID string, authTime time.Time, accessToken string) (string, error) {
	idIssuer, emit, resErr := idTokenIssuerForWebAuthn(deps, client)
	if resErr != nil {
		return "", fmt.Errorf("%w: %v", errWebAuthnIDToken, resErr)
	}
	if !emit {
		return "", nil
	}
	idToken, err := idIssuer.IssueIDToken(ctx, &oidc.IDTokenRequest{
		Subject:     userID,
		Audience:    client.ID,
		AuthTime:    authTime,
		AMR:         []string{"webauthn"},
		AccessToken: accessToken,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", errWebAuthnIDToken, err)
	}
	// Fail-closed encryption: a client that registered
	// id_token_encrypted_response_alg gets a JWE; if encryption is requested
	// but fails, omit the id_token (no cleartext leak) rather than returning
	// the signed form.
	if deps.EncryptIDToken != nil {
		if enc, ok := deps.EncryptIDToken(ctx, client, idToken); ok {
			return enc, nil
		}
		return "", nil
	}
	return idToken, nil
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
	defer func() { _ = r.Body.Close() }()
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
