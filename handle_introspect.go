package sso

import (
	"errors"
	"net/http"
	"strings"
)

// handleIntrospect implements RFC 7662 token introspection. Returns the
// active state + standard metadata claims for a presented access or
// refresh token. Inactive tokens return {active: false} only, with no
// extra metadata — §2.2 mandates this to limit oracle leakage.
//
// Auth: the introspecting client authenticates with client_id +
// client_secret (Basic auth or form body). Per §2.1 any registered
// active client may introspect — production deployments that want
// stronger isolation should layer an authorization middleware that
// checks a custom "introspect" scope or role on the client.
func (s *Server) handleIntrospect(ctx HandlerContext) {
	if err := s.requireDeps(depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		Token         string `json:"token"`
		TokenTypeHint string `json:"token_type_hint"` // "access_token" | "refresh_token"
		ClientID      string `json:"client_id"`
		ClientSecret  string `json:"client_secret"`
	}
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if id, secret, ok := basicClientCreds(ctx.Request()); ok {
		// HTTP Basic auth takes precedence over body fields when present
		// — matches the RFC 6749 §2.3.1 recommendation.
		req.ClientID = id
		req.ClientSecret = secret
	}

	if err := s.authenticateIntrospectionClient(ctx, req.ClientID, req.ClientSecret); err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}

	if req.Token == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}

	// Resolution order is hint-driven: when the hint is "refresh_token"
	// try the refresh store first to avoid an unnecessary access-token
	// signature check, but always fall back to the other tier so a wrong
	// hint doesn't mark a valid token inactive.
	if req.TokenTypeHint == "refresh_token" {
		if body, ok := s.introspectRefresh(ctx, req.Token); ok {
			ctx.JSON(http.StatusOK, body)
			return
		}
		if body, ok := s.introspectAccess(ctx, req.Token); ok {
			ctx.JSON(http.StatusOK, body)
			return
		}
	} else {
		if body, ok := s.introspectAccess(ctx, req.Token); ok {
			ctx.JSON(http.StatusOK, body)
			return
		}
		if body, ok := s.introspectRefresh(ctx, req.Token); ok {
			ctx.JSON(http.StatusOK, body)
			return
		}
	}

	// Unknown / expired / revoked → §2.2 mandates {active: false} only.
	ctx.JSON(http.StatusOK, map[string]any{KeyActive: false})
}

// introspectAccess validates the token as an access token via every
// registered issuer. Returns a populated metadata body on success.
func (s *Server) introspectAccess(ctx HandlerContext, token string) (map[string]any, bool) {
	if len(s.tokenIssuers) == 0 {
		return nil, false
	}
	claims, issuerName, err := s.validateAnyToken(ctx.Request().Context(), token)
	if err != nil || claims == nil {
		return nil, false
	}
	body := map[string]any{
		KeyActive:    true,
		KeyTokenType: TokenTypeBearer,
		KeySub:       claims.Subject,
		KeyIss:       claims.Issuer,
		KeyTokenHint: "access_token",
		KeyStrategy:  issuerName,
	}
	if !claims.ExpiresAt.IsZero() {
		body[KeyExp] = claims.ExpiresAt.Unix()
	}
	if !claims.IssuedAt.IsZero() {
		body[KeyIat] = claims.IssuedAt.Unix()
	}
	if !claims.NotBefore.IsZero() {
		body[KeyNbf] = claims.NotBefore.Unix()
	}
	if len(claims.Audience) > 0 {
		body[KeyAud] = claims.Audience
		// First audience entry conventionally maps to client_id in
		// introspection responses (per RFC 7662 §2.2 "client_id" is
		// optional but useful for downstream policy).
		body[KeyClientID] = claims.Audience[0]
	}
	if len(claims.Scopes) > 0 {
		body[KeyScope] = strings.Join(claims.Scopes, " ")
	}
	return body, true
}

// introspectRefresh queries the optional RefreshTokenInspector. Returns
// (nil, false) when the store doesn't implement the inspector
// extension OR the token is unknown / expired.
func (s *Server) introspectRefresh(ctx HandlerContext, token string) (map[string]any, bool) {
	insp, ok := s.refreshTokenStore.(RefreshTokenInspector)
	if !ok {
		return nil, false
	}
	info, err := insp.Inspect(ctx.Request().Context(), token)
	if err != nil || info == nil {
		return nil, false
	}
	body := map[string]any{
		KeyActive:    true,
		KeyTokenType: TokenTypeBearer,
		KeySub:       info.UserID,
		KeyClientID:  info.ClientID,
		KeyTokenHint: "refresh_token",
	}
	if !info.ExpiresAt.IsZero() {
		body[KeyExp] = info.ExpiresAt.Unix()
	}
	if !info.IssuedAt.IsZero() {
		body[KeyIat] = info.IssuedAt.Unix()
	}
	if len(info.Scopes) > 0 {
		body[KeyScope] = strings.Join(info.Scopes, " ")
	}
	return body, true
}

// authenticateIntrospectionClient verifies the introspecting client's
// credentials via the existing client store. Returns nil on success.
func (s *Server) authenticateIntrospectionClient(ctx HandlerContext, id, secret string) error {
	if id == "" || secret == "" {
		return errors.New("missing client credentials")
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), id)
	if err != nil {
		return err
	}
	if !client.Active {
		return errors.New("inactive client")
	}
	if !clientTenantOK(ctx, client) {
		return errors.New("tenant mismatch")
	}
	return s.clientStore.ValidateSecret(ctx.Request().Context(), id, secret)
}

// basicClientCreds extracts (client_id, client_secret) from an HTTP
// Basic Authorization header, or returns ok=false when absent / malformed.
func basicClientCreds(r *http.Request) (id, secret string, ok bool) {
	if r == nil {
		return "", "", false
	}
	u, p, basicOK := r.BasicAuth()
	if !basicOK {
		return "", "", false
	}
	return u, p, true
}
