package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"time"

	"github.com/snaplink/sso/oauth"
)
// Server's authCodeTTL with a fallback to DefaultAuthCodeTTL.
func (s *Server) issueAuthCode(
	ctx context.Context,
	result *AuthResult,
	req *loginRequest,
	client *Client,
) (string, error) {
	code, err := generateAuthCodeBytes()
	if err != nil {
		return "", fmt.Errorf("generate auth code: %w", err)
	}
	ttl := s.authCodeTTL
	if ttl <= 0 {
		ttl = DefaultAuthCodeTTL
	}
	entry := &oauth.AuthCode{
		UserID:               result.UserID,
		ClientID:             client.ID,
		RedirectURI:          req.RedirectURI,
		Scopes:               append([]string(nil), req.Scope...),
		Nonce:                req.Nonce,
		Provider:             result.Provider,
		AuthTime:             time.Now(),
		AuthMethods:          result.AuthMethods,
		ACR:                  result.AchievedACR,
		Attributes:           result.Attributes,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resources:            append([]string(nil), req.Resource...),
		AuthorizationDetails: oauth.CloneRawJSON(req.AuthorizationDetails),
		ExpiresAt:            time.Now().Add(ttl),
	}
	if err := s.authCodeStore.Issue(ctx, code, entry); err != nil {
		return "", fmt.Errorf("store auth code: %w", err)
	}
	return code, nil
}

// isSecureRedirectURI reports whether the URI satisfies the OAuth 2.1
// §4.1.3 redirect_uri security profile: scheme=https required for
// public hosts; http://localhost (or http://127.0.0.1 / [::1]) on any
// port stays permitted so development workflows don't need a local
// TLS terminator. URIs that fail to parse return false (closed
// default), which collapses to invalid_redirect_uri on the caller.
func isSecureRedirectURI(uri string) bool {
	u, err := neturl.Parse(uri)
	if err != nil || u == nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// isValidPKCEMethod reports whether the named PKCE challenge method is
// one we support. Empty defaults to "plain" per RFC 7636 §4.3 (the
// caller stamps the default after this check); "S256" is the strongly
// recommended method for production.
func isValidPKCEMethod(method string) bool {
	return method == "" || method == PKCEMethodPlain || method == PKCEMethodS256
}

// isPKCEMethodAllowedForClient reports whether the (already-validated)
// PKCE challenge method is permitted under the client's per-client
// allowlist. Empty allowlist = unrestricted (legacy behavior, accept
// anything isValidPKCEMethod accepted). Empty method input means the
// default was applied — must be allowlisted too.
func isPKCEMethodAllowedForClient(method string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == method {
			return true
		}
	}
	return false
}

// verifyPKCE returns true when the supplied verifier derives to the
// stored challenge under the named method. Constant-time comparison
// closes off timing-oracle attacks on the challenge value.
//
// An empty challenge means no PKCE binding was set at issue; callers
// MUST NOT invoke this helper in that case (the exchange skips PKCE
// entirely when info.CodeChallenge is empty — backwards compatible
// with confidential clients).
func verifyPKCE(method, challenge, verifier string) bool {
	switch method {
	case PKCEMethodS256:
		sum := sha256.Sum256([]byte(verifier))
		derived := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) == 1
	case PKCEMethodPlain, "":
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	default:
		return false
	}
}

// generateAuthCodeBytes mints a cryptographically random base64url code.
// Local copy so handler.go doesn't depend on defaultimpl.
func generateAuthCodeBytes() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// issueRefreshToken generates a refresh token, persists it against the
// store, and returns the opaque token string. The TTL is taken from the
// Server's refreshTokenTTL with a fallback to DefaultRefreshTokenTTL.
//
// familyID controls the OAuth Security BCP §4.13 family-tracking
// chain: pass "" on the FIRST issue (login, authz_code, device) to
// mint a new family, or the existing FamilyID on rotation to keep
// every descendant of a single authorization event in one family.
// Stores that don't implement oauth.RefreshTokenFamilyTracker simply
// ignore the value — opt-in hardening.
//
// Callers MUST pre-check s.refreshTokenStore != nil — this helper
// dereferences it unconditionally so a misuse fails loudly during
// testing rather than silently no-op'ing in production.
func (s *Server) issueRefreshToken(
	ctx context.Context,
	userID, clientID, provider string,
	scopes []string,
	attributes map[string]string,
	familyID string,
	resources []string,
	authDetails json.RawMessage,
	sid string,
	clientTTLOverride time.Duration,
) (string, error) {
	token, err := generateAuthCodeBytes() // same 32-byte base64url generator
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	// TTL resolution precedence: per-client override > server-wide
	// configuration > DefaultRefreshTokenTTL. The per-client override
	// lets operators give SPAs (public clients) short refresh tokens
	// while keeping long ones for service clients.
	ttl := clientTTLOverride
	if ttl <= 0 {
		ttl = s.refreshTokenTTL
	}
	if ttl <= 0 {
		ttl = DefaultRefreshTokenTTL
	}
	if familyID == "" {
		// First-issue path: mint a new family. Length matches the
		// token itself — 32 bytes / 256 bits — so collisions across
		// the fleet remain infeasible.
		fid, err := generateAuthCodeBytes()
		if err != nil {
			return "", fmt.Errorf("generate refresh family id: %w", err)
		}
		familyID = fid
	}
	now := time.Now()
	entry := &oauth.RefreshToken{
		UserID:               userID,
		ClientID:             clientID,
		Provider:             provider,
		Scopes:               append([]string(nil), scopes...),
		Attributes:           attributes,
		IssuedAt:             now,
		ExpiresAt:            now.Add(ttl),
		FamilyID:             familyID,
		Resources:            append([]string(nil), resources...),
		AuthorizationDetails: oauth.CloneRawJSON(authDetails),
		SID:                  sid,
	}
	if err := s.refreshTokenStore.Issue(ctx, token, entry); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return token, nil
}

// isScopeSubset reports whether every scope in want is also in have.
// Used by the refresh_token grant to enforce RFC 6749 §6's "MUST NOT
// expand scope" rule — a refresh request may downscope or keep the
// original grant but never widen it.
func isScopeSubset(want, have []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

// providersForClient returns the list of authenticator names this client may
// use. Used by GET /auth/login (provider discovery). If clientID is empty or
// not found, all registered providers are returned (backwards compatible).
func (s *Server) providersForClient(ctx HandlerContext, clientID string) []string {
	all := make([]string, 0, len(s.authenticators))
	for name := range s.authenticators {
		all = append(all, name)
	}
	if clientID == "" || s.clientStore == nil {
		return all
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		return all
	}
	if len(client.AllowedAuthenticators) == 0 {
		return all
	}
	out := make([]string, 0, len(all))
	for _, name := range all {
		if client.IsAuthenticatorAllowed(name) {
			out = append(out, name)
		}
	}
	return out
}

func (s *Server) handleCallback(ctx HandlerContext) {
	code := ctx.Query("code")
	state := ctx.Query("state")
	provider := ctx.Query("provider")

	if code == "" || state == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidCallback))
		return
	}

	var auth Authenticator
	var err error
	if provider != "" {
		// Miss is surfaced via the auth == nil check below, so the lookup
		// error itself is not needed here.
		auth, _ = s.getAuthenticator(provider)
	} else {
		for _, a := range s.authenticators {
			if _, err = a.Callback(context.Background(), &CallbackState{Code: code, State: state}); err == nil {
				auth = a
				break
			}
		}
	}

	if auth == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnknownProvider))
		return
	}

	result, err := auth.Callback(context.Background(), &CallbackState{Code: code, State: state})
	if err != nil {
		s.logger.Error("callback failed", "provider", auth.Name(), "error", err)
		s.recordCallbackFailure(ctx, auth.Name(), ErrCallbackFailed)
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrCallbackFailed))
		return
	}

	user := &User{
		ID:         result.UserID,
		ExternalID: result.ExternalID,
		Provider:   result.Provider,
		Attributes: result.Attributes,
	}
	if s.userProvider != nil {
		if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
			s.logger.Error("failed to upsert user", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
	}

	session, err := s.createSession(ctx, result.UserID)
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	ctx.JSON(http.StatusOK, map[string]string{
		KeySessionID: session.ID,
		KeyStatus:    StatusAuthenticated,
	})
}
