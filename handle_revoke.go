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
	if err := s.requireDeps(depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		Token         string `json:"token"`
		TokenTypeHint string `json:"token_type_hint"`
		ClientID      string `json:"client_id"`
		ClientSecret  string `json:"client_secret"`
	}
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if id, secret, ok := basicClientCreds(ctx.Request()); ok {
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
