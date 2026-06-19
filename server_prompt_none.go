package sso

import (
	"net/http"

	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/internal/auth/login"
)

// handlePromptNone handles the OIDC prompt=none silent renewal branch.
// It validates the client, checks residency, authorizes scopes, and
// delegates to handleSilentRenewal. Always writes a response (either
// renewed tokens or login_required).
func (s *Server) handlePromptNone(ctx HandlerContext, prompts []string, req *login.Request) {
	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMissingClientID))
		return
	}
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
		return
	}
	c, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, s.authzErrorBody(ctx, ErrInvalidClient))
		return
	}
	if !c.Active {
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
		return
	}
	if !clientTenantOK(ctx, c) {
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrTenantMismatch))
		return
	}
	if s.residencyGateLogin(ctx, c.ID, "silent_renewal", c.TenantID) {
		return
	}
	granted, scopeErr := oauth.GrantedScopes(req.Scope, c)
	if scopeErr != nil {
		s.recordLoginFailure(ctx, req.ClientID, "silent_renewal", ErrInvalidScope)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidScope))
		return
	}
	req.Scope = granted
	s.handleSilentRenewal(ctx, prompts, oidc.SilentRenewalRequest{
		ClientID:             req.ClientID,
		Scope:                req.Scope,
		State:                req.State,
		Nonce:                req.Nonce,
		Resource:             req.Resource,
		AuthorizationDetails: req.AuthorizationDetails,
		IDTokenHint:          req.IDTokenHint,
		MaxAge:               req.MaxAge,
	}, c)
}
