package sso

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
)

// handleAuthCodeTokenGrant processes the authorization_code token exchange.
// Extracted from handleToken to keep the main function under 500 lines.
func (s *Server) handleAuthCodeTokenGrant(ctx HandlerContext, client *Client, req struct {
	GrantType    string   `json:"grant_type"`
	Code         string   `json:"code"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RefreshToken string   `json:"refresh_token"`
	Scope        string   `json:"scope"`
	RedirectURI  string   `json:"redirect_uri"`
	CodeVerifier string   `json:"code_verifier"`
	DeviceCode   string   `json:"device_code"`
	AuthReqID    string   `json:"auth_req_id"`
	Resource     []string `json:"resource"`
	SubjectToken       string   `json:"subject_token"`
	SubjectTokenType   string   `json:"subject_token_type"`
	ActorToken         string   `json:"actor_token"`
	ActorTokenType     string   `json:"actor_token_type"`
	Audience           []string `json:"audience"`
	RequestedTokenType string   `json:"requested_token_type"`
	ACRValues          string   `json:"acr_values"`
	ClientAssertion    string   `json:"client_assertion"`
	ClientAssertionType string  `json:"client_assertion_type"`
}, scopes []string, dpopJKT, mtlsX5T string) {
	if s.authCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrAuthCodeNotConfigured))
		return
	}
	if req.Code == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	info, err := s.authCodeStore.Consume(ctx.Request().Context(), req.Code)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}
	if info.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}
	if info.RedirectURI != "" && req.RedirectURI != info.RedirectURI {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRedirectURI))
		return
	}
	if info.CodeChallenge != "" {
		if l := len(req.CodeVerifier); l < PKCEVerifierMinLen || l > PKCEVerifierMaxLen {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		if !verifyPKCE(info.CodeChallengeMethod, info.CodeChallenge, req.CodeVerifier) {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
	}
	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}
	scopes = info.Scopes
	if len(scopes) == 0 {
		scopes = strings.Split(req.Scope, " ")
	}
	resources := info.Resources
	if len(resources) == 0 {
		resources = req.Resource
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, info.UserID)
	authTime := info.AuthTime
	if authTime.IsZero() {
		authTime = time.Now()
	}
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID: issuedSub, Provider: info.Provider, Claims: info.Attributes,
		Resources:            resources,
		ClientID:             client.ID,
		AuthTime:             authTime,
		AMR:                  handler.AmrOrProvider(info.AuthMethods, info.Provider),
		ACR:                  info.ACR,
		AuthorizationDetails: oauth.CloneRawJSON(info.AuthorizationDetails),
		SID:                  info.SID,
		TTL:                  client.AccessTokenTTL,
		ConfirmationJKT:      dpopJKT,
		ConfirmationX5TS256:  mtlsX5T,
	}, scopes)
	if err != nil {
		s.logErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordTokenIssued(ctx, client.ID, strategy, info.UserID)
	s.recordSubjectClientAccess(ctx.Request().Context(), info.UserID, client.ID)
	resp := map[string]any{
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     dpopTokenTypeOr(token.TokenType, dpopJKT),
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
	}
	if s.refreshTokenStore != nil {
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			info.UserID, client.ID, info.Provider, scopes, info.Attributes, "", info.Resources,
			info.AuthorizationDetails, info.SID, client.RefreshTokenTTL)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err, "client", client.ID, "user", info.UserID)
		} else {
			resp[KeyRefreshToken] = rt
			s.recordRefreshTokenIssued(ctx, client.ID, info.UserID, false)
		}
	}
	var deviceSecretValue string
	if slices.Contains(info.Scopes, ScopeDeviceSSO) && s.deviceSecretStore != nil {
		if ds, dsErr := s.issueDeviceSecret(ctx.Request().Context(), info.UserID, info.SID, client.ID); dsErr != nil {
			s.logger.Error("device secret issue failed", "error", dsErr, "client", client.ID, "user", info.UserID)
		} else {
			deviceSecretValue = ds
		}
	}
	if slices.Contains(info.Scopes, ScopeOpenID) {
		idIssuer, emit, idErr := s.idTokenIssuerForClient(client)
		if idErr != nil {
			s.logger.Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID, "user", info.UserID)
		} else if emit {
			idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:      issuedSub,
				Audience:     client.ID,
				Nonce:        info.Nonce,
				AuthTime:     authTime,
				AMR:          handler.AmrOrProvider(info.AuthMethods, info.Provider),
				ACR:          info.ACR,
				Claims:       info.Attributes,
				AccessToken:  token.AccessToken,
				DeviceSecret: deviceSecretValue,
			})
			if err != nil {
				s.logger.Error("id token issue failed", "error", err, "client", client.ID, "user", info.UserID)
			} else if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
				resp[KeyIDToken] = enc
				s.recordIDTokenIssued(ctx, client.ID, info.UserID)
			}
		}
	}
	if deviceSecretValue != "" {
		resp[KeyDeviceSecret] = deviceSecretValue
	}
	ctx.JSON(http.StatusOK, resp)
}
