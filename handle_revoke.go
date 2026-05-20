package sso

import "net/http"

// handleRevoke implements RFC 7009 token revocation. Per-token
// revocation that's complementary to /logout (which is session-scoped).
//
// Auth: same client credentials as /token/introspect. Per §2 any
// registered active client may revoke — but the server MUST NOT
// distinguish revocation of an unknown token from a successful
// revocation (§2.2), so the wire response is always 200 OK with an
// empty body when the credentials are valid, regardless of whether
// the token existed.
//
// token_type_hint is honored as an optimization (try the named tier
// first) but the server still attempts the other tier on miss, so a
// wrong hint doesn't leave the token alive.
func (s *Server) handleRevoke(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		Token               string `json:"token"`
		TokenTypeHint       string `json:"token_type_hint"`
		ClientID            string `json:"client_id"`
		ClientSecret        string `json:"client_secret"`
		ClientAssertion     string `json:"client_assertion"`      // RFC 7521 + 7523
		ClientAssertionType string `json:"client_assertion_type"` // RFC 7521 + 7523
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if id, secret, ok := basicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
	}

	// RFC 7521/7523 JWT bearer client auth on /token/revoke.
	if req.ClientAssertion != "" || req.ClientAssertionType != "" {
		if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		assertedID, err := verifyJWTClientAssertion(
			ctx.Request().Context(),
			req.ClientAssertion,
			req.ClientID,
			s.clientStore,
			s.resolveIssuer(ctx),
			s.jtiReplayStore,
		)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
			return
		}
		req.ClientID = assertedID
		c, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
		if err != nil || c == nil || !c.Active || !clientTenantOK(ctx, c) {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
			return
		}
	} else if err := s.authenticateIntrospectionClient(ctx, req.ClientID, req.ClientSecret); err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}

	if req.Token == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}

	// Best-effort across both tiers. Errors are intentionally ignored
	// per §2.2 — the response is always 200 OK on valid credentials.
	if req.TokenTypeHint == "refresh_token" {
		s.revokeRefresh(ctx, req.Token)
		s.revokeAccess(ctx, req.Token)
	} else {
		s.revokeAccess(ctx, req.Token)
		s.revokeRefresh(ctx, req.Token)
	}

	ctx.JSON(http.StatusOK, map[string]any{})
}

// revokeAccess delegates to the existing per-issuer revocation chain.
func (s *Server) revokeAccess(ctx HandlerContext, token string) {
	if len(s.tokenIssuers) == 0 {
		return
	}
	_ = s.revokeAcrossIssuers(ctx.Request().Context(), token)
}

// revokeRefresh deletes via the optional RefreshTokenInspector.Delete
// extension. No-op when the store doesn't implement the extension —
// callers in that situation must rely on TTL expiry.
func (s *Server) revokeRefresh(ctx HandlerContext, token string) {
	insp, ok := s.refreshTokenStore.(RefreshTokenInspector)
	if !ok {
		return
	}
	_ = insp.Delete(ctx.Request().Context(), token)
}

// handleRevokeAll implements the "logout everywhere" endpoint. The
// user presents a bearer token; the server reads sub + aud from its
// claims, then kills every refresh token bound to that
// (subject, client) pair via the optional RefreshTokenSubjectIndex
// extension. The presented access token is also revoked via the
// normal per-issuer path so it stops working immediately.
//
// Useful for a "sign out of all devices" button — one round trip
// instead of per-device per-token revocation.
//
// Requires the RefreshTokenStore to implement
// RefreshTokenSubjectIndex; without it, the response is 501.
//
// Authentication: bearer token only (not client credentials). The
// user is the actor — they're authorizing the revocation of their
// own tokens.
func (s *Server) handleRevokeAll(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(depTokenIssuer); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}
	idx, ok := s.refreshTokenStore.(RefreshTokenSubjectIndex)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrRefreshTokenNotConfigured))
		return
	}

	bearer := bearerToken(ctx.Request())
	if bearer == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer)
	if err != nil || claims == nil || claims.Subject == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}

	deleted, err := idx.DeleteAllForSubject(ctx.Request().Context(), claims.Subject, clientID)
	if err != nil {
		s.logger.Error("revoke-all failed", "error", err, "subject", claims.Subject)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// Also revoke the presented access token across all issuers so it
	// stops working immediately — without this, the bearer the caller
	// just used would keep working until expiry, which is surprising
	// for a "logout everywhere" semantic.
	_ = s.revokeAcrossIssuers(ctx.Request().Context(), bearer)

	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:                StatusOK,
		"refresh_tokens_revoked": deleted,
	})
}
