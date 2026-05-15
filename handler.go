package sso

import (
	"context"
	"net/http"
	"strings"
)

// errorBody returns the standard error envelope { "error": code }.
func errorBody(code string) map[string]string {
	return map[string]string{KeyError: code}
}

// errorBodyWithDescription returns { "error": code, "error_description": desc }.
func errorBodyWithDescription(code, desc string) map[string]string {
	return map[string]string{KeyError: code, KeyErrorDescription: desc}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get(HeaderAuthorization)
	if !strings.HasPrefix(h, BearerPrefix) {
		return ""
	}
	return strings.TrimPrefix(h, BearerPrefix)
}

func (s *Server) handleHealth(ctx HandlerContext) {
	ctx.JSON(http.StatusOK, map[string]string{
		KeyStatus: StatusOK,
		KeyIssuer: s.issuer,
	})
}

func (s *Server) handleLogin(ctx HandlerContext) {
	var req struct {
		Provider   string            `json:"provider"`
		Credential map[string]string `json:"credential"`
		ClientID   string            `json:"client_id"`
		Scope      []string          `json:"scope"`
		State      string            `json:"state"`
	}
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(ErrInvalidRequest, err.Error()))
		return
	}

	if req.Provider == "" {
		ctx.JSON(http.StatusOK, map[string]any{KeyProviders: s.providersForClient(ctx, req.ClientID)})
		return
	}

	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrClientStoreNotConfigured))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidClient)
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}
	if !client.Active {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInactiveClient)
		ctx.JSON(http.StatusForbidden, errorBody(ErrInactiveClient))
		return
	}
	if !client.IsAuthenticatorAllowed(req.Provider) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrAuthenticatorNotAllowed)
		ctx.JSON(http.StatusForbidden, errorBody(ErrAuthenticatorNotAllowed))
		return
	}

	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnsupportedProvider))
		return
	}

	loginURL := auth.LoginURL(req.State)
	if loginURL != "" {
		ctx.Redirect(http.StatusFound, loginURL)
		return
	}

	result, err := auth.Authenticate(ctx.Request().Context(), &AuthRequest{
		Provider:   req.Provider,
		Credential: req.Credential,
		ClientID:   req.ClientID,
		Scope:      req.Scope,
		State:      req.State,
	})
	if err != nil {
		s.logger.Error("authentication failed", "provider", req.Provider, "error", err)
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidCredentials)
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidCredentials))
		return
	}

	if s.userProvider != nil {
		user := &User{
			ID:         result.UserID,
			ExternalID: result.ExternalID,
			Provider:   result.Provider,
			Attributes: result.Attributes,
		}
		if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
			s.logger.Error("failed to upsert user", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
	}

	if s.sessionMgr == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrSessionMgrNotConfigured))
		return
	}
	session, err := s.sessionMgr.Create(ctx.Request().Context(), result.UserID)
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		s.logger.Error("no token strategy for client", "client", client.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:       result.UserID,
		Provider: result.Provider,
		Claims:   result.Attributes,
	}, req.Scope)
	if err != nil {
		s.logger.Error("failed to issue token", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	s.recordLoginSuccess(ctx, client.ID, req.Provider, strategy, result.UserID, session.ID)

	// Geo enrichment: if the authenticator didn't supply a
	// language hint, fall back to whatever the geo middleware
	// stashed on the request. Authenticators with a stronger
	// signal (SIM region, account default, explicit user pref)
	// override the geo guess by setting it themselves.
	if result.RecommendedLanguage == "" {
		if info, ok := GeoFromHandlerContext(ctx); ok {
			result.RecommendedLanguage = info.RecommendedLanguage
		}
	}

	resp := map[string]any{
		KeySessionID:     session.ID,
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyRefreshToken:  token.RefreshToken,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
	}
	if result.RecommendedLanguage != "" {
		resp[KeyRecommendedLang] = result.RecommendedLanguage
	}
	if s.embedPermissions {
		roles, perms, menus := s.resolvePermissionsForLogin(ctx.Request().Context(), result.UserID, client.ID)
		resp[KeyRoles] = roles
		resp[KeyPermissions] = perms
		resp[KeyMenus] = menus
	}
	ctx.JSON(http.StatusOK, resp)
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
		auth, err = s.getAuthenticator(provider)
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
		s.userProvider.CreateOrUpdate(ctx.Request().Context(), user)
	}

	session, err := s.sessionMgr.Create(ctx.Request().Context(), result.UserID)
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

func (s *Server) handleToken(ctx HandlerContext) {
	if err := s.requireDeps(depTokenIssuer, depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		GrantType    string `json:"grant_type"`
		Code         string `json:"code"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}
	if err := s.clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClientSecret))
		return
	}

	var scopes []string
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
	}

	switch req.GrantType {
	case GrantAuthorizationCode:
		ctx.JSON(http.StatusOK, map[string]string{
			KeyAccessToken: "TODO:implement_code_exchange",
			KeyTokenType:   TokenTypeBearer,
		})
	case GrantRefreshToken:
		ctx.JSON(http.StatusOK, map[string]string{
			KeyAccessToken: "TODO:implement_refresh",
			KeyTokenType:   TokenTypeBearer,
		})
	case GrantClientCredentials:
		strategy, ti, err := s.issuerForClient(client)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
			return
		}
		token, err := ti.Issue(ctx.Request().Context(), &Subject{ID: client.ID}, scopes)
		if err != nil {
			s.logger.Error("token issuance failed", "strategy", strategy, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		s.recordTokenIssued(ctx, client.ID, strategy, client.ID)
		ctx.JSON(http.StatusOK, map[string]any{
			KeyAccessToken:   token.AccessToken,
			KeyTokenType:     token.TokenType,
			KeyExpiresIn:     token.ExpiresIn,
			KeyScope:         token.Scope,
			KeyTokenStrategy: strategy,
		})
	default:
		ctx.JSON(http.StatusBadRequest, map[string]any{
			KeyError:           ErrUnsupportedGrantType,
			KeySupportedGrants: SupportedGrants,
		})
	}
}

func (s *Server) handleUserInfo(ctx HandlerContext) {
	if err := s.requireDeps(depTokenIssuer, depUserProvider); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}

	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	user, err := s.userProvider.GetByID(ctx.Request().Context(), claims.Subject)
	if err != nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrUserNotFound))
		return
	}

	ctx.JSON(http.StatusOK, user)
}

func (s *Server) handleLogout(ctx HandlerContext) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	// Body is optional — bearer-only logouts are allowed.
	_ = ctx.Bind(&req)

	bearer := bearerToken(ctx.Request())

	if req.SessionID == "" && bearer == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrSessionIDOrBearerRequired))
		return
	}

	revoked := []string{}
	if req.SessionID != "" && s.sessionMgr != nil {
		if err := s.sessionMgr.Destroy(ctx.Request().Context(), req.SessionID); err != nil {
			s.logger.Error("logout: destroy session failed", "error", err)
		} else {
			revoked = append(revoked, RevokedSession)
		}
	}
	if bearer != "" && len(s.tokenIssuers) > 0 {
		issuersHit := s.revokeAcrossIssuers(ctx.Request().Context(), bearer)
		for range issuersHit {
			revoked = append(revoked, RevokedToken)
		}
	}

	s.recordLogout(ctx, req.SessionID, revoked)

	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:  StatusLoggedOut,
		KeyRevoked: revoked,
	})
}

func (s *Server) handleSendCode(ctx HandlerContext) {
	var req struct {
		Provider string `json:"provider"`
		Target   string `json:"target"`
	}
	if err := ctx.Bind(&req); err != nil || req.Provider == "" || req.Target == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrProviderAndTargetRequired))
		return
	}

	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnsupportedProvider))
		return
	}

	sender, ok := auth.(CodeSender)
	if !ok {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrProviderDoesNotSendCodes))
		return
	}

	if err := sender.SendCode(ctx.Request().Context(), req.Target); err != nil {
		s.logger.Error("send code failed", "provider", req.Provider, "error", err)
		s.recordCodeSent(ctx, req.Provider, req.Target, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrSendFailed))
		return
	}

	s.recordCodeSent(ctx, req.Provider, req.Target, true)

	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusSent})
}

func (s *Server) handleGetClient(ctx HandlerContext) {
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrClientStoreNotConfigured))
		return
	}

	clientID := ctx.Param("id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrClientNotFound))
		return
	}

	ctx.JSON(http.StatusOK, client)
}
