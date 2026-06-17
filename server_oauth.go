package sso

import (
	"context"
	"net/http"
	"time"

	"github.com/snaplink/sso/oauth"
)

// issueAuthCode delegates to oauth.IssueAuthCode.
func (s *Server) issueAuthCode(ctx context.Context, result *AuthResult, req *loginRequest, client *Client) (string, error) {
	return oauth.IssueAuthCode(ctx, oauth.IssueAuthCodeParams{
		AuthCodeTTL:          s.authCodeTTL,
		AuthCodeStore:        s.authCodeStore,
		UserID:               result.UserID,
		ClientID:             client.ID,
		RedirectURI:          req.RedirectURI,
		Scopes:               req.Scope,
		Nonce:                req.Nonce,
		Provider:             result.Provider,
		AuthMethods:          result.AuthMethods,
		ACR:                  result.AchievedACR,
		Attributes:           result.Attributes,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resources:            req.Resource,
		AuthorizationDetails: req.AuthorizationDetails,
	})
}

// isSecureRedirectURI delegates to oauth.IsSecureRedirectURI.
func isSecureRedirectURI(uri string) bool {
	return oauth.IsSecureRedirectURI(uri)
}

// isValidPKCEMethod delegates to oauth.IsValidPKCEMethod.
func isValidPKCEMethod(method string) bool {
	return oauth.IsValidPKCEMethod(method)
}

// isPKCEMethodAllowedForClient delegates to oauth.IsPKCEMethodAllowedForClient.
func isPKCEMethodAllowedForClient(method string, allowed []string) bool {
	return oauth.IsPKCEMethodAllowedForClient(method, allowed)
}

// verifyPKCE delegates to oauth.VerifyPKCE.
func verifyPKCE(method, challenge, verifier string) bool {
	return oauth.VerifyPKCE(method, challenge, verifier)
}

// generateAuthCodeBytes delegates to oauth.GenerateAuthCodeBytes.
func generateAuthCodeBytes() (string, error) {
	return oauth.GenerateAuthCodeBytes()
}

// issueRefreshToken delegates to oauth.IssueRefreshToken.
func (s *Server) issueRefreshToken(
	ctx context.Context,
	userID, clientID, provider string,
	scopes []string,
	attributes map[string]string,
	familyID string,
	resources []string,
	authDetails []byte,
	sid string,
	clientTTLOverride time.Duration,
) (string, error) {
	return oauth.IssueRefreshToken(ctx, oauth.IssueRefreshTokenParams{
		RefreshTokenTTL:    s.refreshTokenTTL,
		RefreshTokenStore:  s.refreshTokenStore,
		UserID:             userID,
		ClientID:           clientID,
		Provider:           provider,
		Scopes:             scopes,
		Attributes:         attributes,
		FamilyID:           familyID,
		Resources:          resources,
		AuthorizationDetails: authDetails,
		SID:                sid,
		ClientTTLOverride:  clientTTLOverride,
	})
}

// isScopeSubset delegates to oauth.IsScopeSubset.
func isScopeSubset(want, have []string) bool {
	return oauth.IsScopeSubset(want, have)
}

// providersForClient returns the list of authenticator names this client may use.
// This remains in root as it's a Server adapter method.
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

// handleCallback handles the OAuth callback. This remains in root as it's a Server HTTP handler.
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

	session, err := s.createSession(ctx, result.UserID, "")
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
