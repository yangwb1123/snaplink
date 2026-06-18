package sso

import (
	"net/http"

	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/security"
)

// resolveLoginRequest handles JAR request_uri URL-fetch and PAR
// consume. Returns true if the request is fully handled (caller
// should return immediately).
func (s *Server) resolveLoginRequest(ctx HandlerContext, req *login.Request) bool {
	if req.RequestURI != "" && security.IsJARFetchableURI(req.RequestURI) {
		if s.jarFetcher == nil {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return true
		}
		if req.ClientID == "" || s.clientStore == nil {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return true
		}
		c, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return true
		}
		if !security.IsRequestURIAllowed(req.RequestURI, c.AllowedRequestURIs) {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return true
		}
		body, err := s.jarFetcher.Fetch(ctx.Request().Context(), req.RequestURI)
		if err != nil {
			s.logErrorCtx(ctx, "jar fetch failed", "error", err, "client", req.ClientID, "uri", req.RequestURI)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return true
		}
		req.Request = string(body)
		return false
	}

	if req.RequestURI != "" {
		if s.parStore == nil {
			ctx.JSON(http.StatusNotImplemented, s.authzErrorBody(ctx, ErrPARNotConfigured))
			return true
		}
		stored, err := s.parStore.Consume(ctx.Request().Context(), req.RequestURI)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return true
		}
		if stored.ClientID != "" {
			req.ClientID = stored.ClientID
		}
		if stored.ResponseType != "" {
			req.ResponseType = stored.ResponseType
		}
		if stored.RedirectURI != "" {
			req.RedirectURI = stored.RedirectURI
		}
		if len(stored.Scope) > 0 {
			req.Scope = stored.Scope
		}
		if stored.State != "" {
			req.State = stored.State
		}
		if stored.Nonce != "" {
			req.Nonce = stored.Nonce
		}
		if stored.CodeChallenge != "" {
			req.CodeChallenge = stored.CodeChallenge
			req.CodeChallengeMethod = stored.CodeChallengeMethod
		}
		if len(stored.Resource) > 0 {
			req.Resource = stored.Resource
		}
		if len(stored.AuthorizationDetails) > 0 {
			req.AuthorizationDetails = oauth.CloneRawJSON(stored.AuthorizationDetails)
		}
		if stored.LoginHint != "" {
			req.LoginHint = stored.LoginHint
		}
		if stored.ResponseMode != "" {
			req.ResponseMode = stored.ResponseMode
		}
		if stored.ACRValues != "" {
			req.ACRValues = stored.ACRValues
		}
		if stored.UILocales != "" {
			req.UILocales = stored.UILocales
		}
		if len(stored.Claims) > 0 {
			req.Claims = oauth.CloneRawJSON(stored.Claims)
		}
		return false
	}
	return false
}
