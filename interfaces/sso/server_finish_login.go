package sso

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
)

// matter whether MFA gated the request or not.
func (s *Server) finishLogin(ctx HandlerContext, result *AuthResult, req login.Request, client *Client) {
	state := req.State
	if s.upsertLoginUser(ctx, result, state) {
		return
	}

	// Non-blocking credential-health signal. Emitted once here so it covers
	// every downstream branch (code flow + direct mint) and both the primary
	// login and the MFA-resumed re-entry, which all funnel through finishLogin.
	// It NEVER blocks login and NEVER rides on the wire or into any token —
	// AuthResult.CredentialHealth is json:"-", so generic serialization strips
	// it; the MFA step-up path re-threads it via mfaResumeState.CredentialHealth
	// so this audit still fires after resume. nil = no signal.
	s.recordCredentialHealth(ctx, client.ID, result.UserID, result.CredentialHealth)

	granted, halted := s.validateAndAuthorizeScope(ctx, &req, client)
	if halted {
		return
	}
	req.Scope = granted

	// Consent gate (opt-in via WithConsentStore, nil = no-op). Runs AFTER scope
	// authorization so req.Scope is the granted set that will appear in the
	// issued token — the grant we check and record is authoritative for them.
	if s.consentStore != nil {
		if s.handleConsentGate(ctx, result.UserID, client, req.Scope, req.Prompt, req.ConsentChallengeID, req.AuthorizationDetails) {
			return
		}
	}

	// JIT org-membership provisioning (opt-in): a user logging in through a
	// tenant-bound client who isn't yet on that org's roster is auto-added as a
	// member, so federated users appear in their org without manual invitation.
	// Fail-open + best-effort — never blocks login.
	s.ensureJITMembership(ctx, client, result.UserID)

	s.finishLoginDispatch(ctx, result, &req, client, state)
}

// finishLoginDispatch routes the authenticated request to its response_type
// branch. OAuth 2.0 authorization_code: instead of minting a token here,
// persist a short-lived code bound to (user, client, redirect_uri) and return
// it so the relying party can exchange it via /token. The branch always owns
// the response. Any other non-empty response_type except "token" rejects with
// unsupported_response_type; empty and "token" direct-mint.
func (s *Server) finishLoginDispatch(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client, state string) {
	if req.ResponseType == "code" {
		s.finishLoginCodeFlow(ctx, result, req, client)
		return
	}
	if req.ResponseType != "" && req.ResponseType != "token" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrUnsupportedResponseType, state))
		return
	}

	s.finishLoginDirectMint(ctx, result, req, client)
}

// upsertLoginUser provisions/refreshes the local user record from the
// authentication result when a UserProvider is wired. On a store failure it has
// ALREADY written the exact 500 internal body and returns halted=true; the
// caller must return immediately. No provider = no-op (halted=false).
func (s *Server) upsertLoginUser(ctx HandlerContext, result *AuthResult, state string) bool {
	if s.userProvider == nil {
		return false
	}
	user := &User{
		ID:         result.UserID,
		ExternalID: result.ExternalID,
		Provider:   result.Provider,
		Attributes: result.Attributes,
	}
	if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
		s.logger.Error("failed to upsert user", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrInternal, state))
		return true
	}
	return false
}

// validateAndAuthorizeScope runs the pre-side-effect gates shared by both login
// branches and resolves the granted scope set. On any halt it has ALREADY written
// the exact 400 body (unsupported_response_type / invalid_request / invalid_scope)
// and returns halted=true; the caller must return immediately. On success it
// returns the GRANTED scope set (validated, or defaulted to the client's
// AllowedScopes when the request named no scope); the caller assigns it to
// req.Scope BEFORE the consent gate so every downstream consumer sees it.
func (s *Server) validateAndAuthorizeScope(ctx HandlerContext, req *login.Request, client *Client) ([]string, bool) {
	// OAuth 2.1 strict mode: response_type=token (implicit) is
	// retired by OAuth 2.1; empty response_type (which defaulted
	// to direct-mint in OAuth 2.0) is treated the same way under
	// strict mode. Both reject with unsupported_response_type
	// — strict mode requires explicit response_type=code.
	if s.oauth21Strict && req.ResponseType != "code" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrUnsupportedResponseType, req.State))
		return nil, true
	}

	// OIDC Form Post Response Mode 1.0 — validate response_mode
	// early so a bad value fails BEFORE any side-effects (auth code
	// issue, session create). Empty is always valid and falls
	// through to the response_type's default mode.
	if req.ResponseMode != "" && !s.isValidResponseMode(req.ResponseMode) {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, req.State))
		return nil, true
	}

	// Scope authorization (RFC 6749 §3.3) — the access-control gate on
	// what the issued token may carry. Run here, AFTER authentication and
	// the tenant/residency gates, so it can never be a pre-auth probe and
	// covers BOTH the authorization_code branch (the granted set is baked
	// into the stored code) and the direct-mint branch below. Mirrors the
	// tenant_mismatch / residency gates: record the failure + emit the
	// authz error body carrying the RFC 9207 iss. The granted set is
	// validated, or defaulted to the client's AllowedScopes when the
	// request named no scope, so every downstream consumer — auth code,
	// direct mint, refresh, id_token gate — sees the authorized scope.
	// Empty allowlist = unrestricted = req.Scope passes through unchanged
	// (byte-identical for clients without one).
	granted, scopeErr := oauth.GrantedScopes(req.Scope, client)
	if scopeErr != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidScope)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidScope, req.State))
		return nil, true
	}
	return granted, false
}

// finishLoginDirectMint is the OAuth 2.0 direct-mint branch (response_type
// empty / token): create a session, issue the access token (+ server-managed
// refresh token, Native SSO device_secret, and OIDC id_token when in scope), and
// return them. Extracted verbatim from finishLogin to keep that orchestrator
// within the complexity budget; req.Scope is already the granted set.
func (s *Server) finishLoginDirectMint(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client) {
	state := req.State
	if s.sessionMgr == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrSessionMgrNotConfigured, state))
		return
	}
	session, err := s.createSession(ctx, result.UserID, client.ID, client.TenantID)
	if err != nil {
		if errors.Is(err, errMaxActiveSessions) {
			// Token-policy max_active_sessions cap: a clean login-time refusal.
			// The specific dimension stays off the wire (metric + log only).
			ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, ErrAccessDenied, state))
			return
		}
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrInternal, state))
		return
	}
	strategy, token, issuedSub, err := s.mintAccessToken(ctx, result, req, client, session)
	if err != nil {
		// mintAccessToken has already written the exact 500 body.
		return
	}

	s.recordLoginSuccess(ctx, client.ID, req.Provider, strategy, result.UserID, session.ID)
	s.recordSubjectClientAccess(ctx.Request().Context(), result.UserID, client.ID)
	fillGeoFromContext(ctx, result)

	resp := map[string]any{
		KeySessionID:     session.ID,
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyRefreshToken:  token.RefreshToken,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
		KeyIss:           s.resolveIssuer(ctx),
	}
	s.augmentDirectMintResponse(ctx, result, req, client, session, issuedSub, token, resp)
	s.applyLoginResponseExtras(ctx, result, client.ID, resp)
	ctx.JSON(http.StatusOK, resp)
}

// mintAccessToken resolves the per-client token strategy, applies the pairwise
// subject pseudonym, and issues the access token for the direct-mint branch. It
// returns the issued subject so the caller threads the SAME value into the
// id_token (it MUST NOT be recomputed). On any failure it has ALREADY written
// the exact 500 body (no_token_strategy / internal) and returns a non-nil error;
// the caller returns immediately.
func (s *Server) mintAccessToken(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client, session *Session) (string, *Token, string, error) {
	state := req.State
	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		s.logger.Error("no token strategy for client", "client", client.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrNoTokenStrategy, state))
		return "", nil, "", err
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, result.UserID)
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:                   issuedSub,
		Provider:             result.Provider,
		Claims:               result.Attributes,
		Resources:            append([]string(nil), req.Resource...),
		ClientID:             client.ID,
		AuthTime:             time.Now(),
		AMR:                  handler.AmrForResult(result),
		ACR:                  result.AchievedACR,
		AuthorizationDetails: oauth.CloneRawJSON(req.AuthorizationDetails),
		SID:                  session.ID,
		TTL:                  client.AccessTokenTTL,
		RequestedClaims:      oauth.CloneRawJSON(req.Claims),
	}, req.Scope)
	if err != nil {
		s.logger.Error("failed to issue token", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrInternal, state))
		return "", nil, "", err
	}
	return strategy, token, issuedSub, nil
}

// augmentDirectMintResponse layers the optional credentials onto the direct-mint
// response in order: the server-managed refresh token (overriding the issuer's),
// then the Native SSO device_secret, then the OIDC id_token. The device_secret is
// minted BEFORE the id_token so its ds_hash can ride the id_token. issuedSub is
// the value returned by mintAccessToken and is threaded into emitLoginIDToken
// unchanged. Each step FAILS OPEN: an outage logs a logger.Error and omits only
// that field, never blocking the login.
func (s *Server) augmentDirectMintResponse(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client, session *Session, issuedSub string, token *Token, resp map[string]any) {
	// When a oauth.RefreshTokenStore is wired, server-managed refresh tokens
	// override whatever the underlying TokenIssuer returned — that way the OAuth
	// refresh_token grant works uniformly regardless of which issuer minted the
	// access token. Fail-open: a refresh-token store outage doesn't block the
	// login (user gets an access_token until expiry), surfaced as a logger.Error.
	if s.refreshTokenStore != nil {
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			result.UserID, client.ID, result.Provider, req.Scope, result.Attributes, "", req.Resource,
			req.AuthorizationDetails, session.ID,
			// RFC 9068 §2.2: persist the live login's amr/acr/auth_time so a
			// later refresh rotation re-stamps the SAME authentication context
			// (mirrors the access token's Subject above) instead of collapsing
			// amr to the provider and dropping acr/auth_time.
			oauth.RefreshAuthContext{AMR: handler.AmrForResult(result), ACR: result.AchievedACR, AuthTime: time.Now()},
			client.RefreshTokenTTL, "") // login flow: no DPoP at /auth/login; refresh token unbound
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err, "client", client.ID, "user", result.UserID)
		} else {
			resp[KeyRefreshToken] = rt
			s.recordRefreshTokenIssued(ctx, client.ID, result.UserID, false)
		}
	}
	// Native SSO 1.0: when the client was granted device_sso and a device-secret
	// store is wired, mint a device_secret BEFORE the id_token so its ds_hash can
	// ride the id_token. Fail-open: issuance failure logs and omits the secret.
	var deviceSecretValue string
	if slices.Contains(req.Scope, ScopeDeviceSSO) && s.deviceSecretStore != nil {
		if ds, dsErr := s.issueDeviceSecret(ctx.Request().Context(), result.UserID, session.ID, client.ID); dsErr != nil {
			s.logger.Error("device secret issue failed", "error", dsErr, "client", client.ID, "user", result.UserID)
		} else {
			deviceSecretValue = ds
		}
	}
	if slices.Contains(req.Scope, ScopeOpenID) {
		if enc, ok := s.emitLoginIDToken(ctx, result, req, client, issuedSub, session.ID, token.AccessToken, deviceSecretValue); ok {
			resp[KeyIDToken] = enc
			s.recordIDTokenIssued(ctx, client.ID, result.UserID)
		}
	}
	s.applySessionManagement(ctx, req, client, session, resp)
	if deviceSecretValue != "" {
		resp[KeyDeviceSecret] = deviceSecretValue
	}
}

// fillGeoFromContext backfills the AuthResult's country/language from the geo
// middleware's stash when the authenticator supplied no stronger signal (SIM
// region, account default, explicit pref). One ctx.Get to avoid two round trips.
func fillGeoFromContext(ctx HandlerContext, result *AuthResult) {
	if result.CountryCode != "" && result.RecommendedLanguage != "" {
		return
	}
	info, ok := GeoFromHandlerContext(ctx)
	if !ok {
		return
	}
	if result.CountryCode == "" {
		result.CountryCode = info.CountryCode
	}
	if result.RecommendedLanguage == "" {
		result.RecommendedLanguage = info.RecommendedLanguage
	}
}

// emitLoginIDToken issues the OIDC id_token for the direct-mint login and returns
// the (optionally JWE-encrypted) token + ok=true to add it to the response.
// Errors FAIL OPEN — a misconfigured/unresolvable id_token issuer must not block
// the underlying authentication; the RP simply won't receive an id_token. OIDC
// Core §5.5: the claims-parameter id_token.acr request is enforced upstream, so
// it is not re-projected here.
func (s *Server) emitLoginIDToken(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client, issuedSub, sid, accessToken, deviceSecret string) (string, bool) {
	idIssuer, emit, idErr := s.idTokenIssuerForClient(client)
	if idErr != nil {
		// Tenant mapping named an unregistered issuer — fail closed (omit
		// id_token) rather than sign with the shared key.
		s.logger.Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID, "user", result.UserID)
		return "", false
	}
	if !emit {
		return "", false
	}
	// Project the RP-requested claims (OIDC Core §5.5) so id_token only carries
	// what the client asked for — shrinking token size and respecting the client's
	// declared claim preferences. When no claims parameter was sent, all attributes
	// are included unchanged (backward compatible).
	claims := result.Attributes
	if len(req.Claims) > 0 {
		claims = oidc.ProjectIDTokenClaims(claims, req.Claims)
	}
	idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
		Subject:         issuedSub,
		Audience:        client.ID,
		Nonce:           req.Nonce,
		AuthTime:        time.Now(),
		AMR:             handler.AmrForResult(result),
		ACR:             result.AchievedACR,
		Claims:          claims,
		SID:             sid,
		AccessToken:     accessToken,
		DeviceSecret:    deviceSecret,
		RequestedClaims: req.Claims,
	})
	if err != nil {
		s.logger.Error("id token issue failed", "error", err, "client", client.ID, "user", result.UserID)
		return "", false
	}
	return s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken)
}

// applyLoginResponseExtras adds the optional UX/governance fields to the login
// response: geo country/language hints, the serving_region marker (UX, not a
// security signal), and embedded roles/permissions/menus when enabled.
func (s *Server) applyLoginResponseExtras(ctx HandlerContext, result *AuthResult, clientID string, resp map[string]any) {
	if result.CountryCode != "" {
		resp[KeyCountryCode] = result.CountryCode
	}
	if result.RecommendedLanguage != "" {
		resp[KeyRecommendedLang] = result.RecommendedLanguage
	}
	if servingRegion, ok := region.FromHandlerContext(ctx); ok && servingRegion != "" {
		resp[KeyServingRegion] = string(servingRegion)
	}
	if s.embedPermissions {
		roles, perms, menus := s.resolvePermissionsForLogin(ctx.Request().Context(), result.UserID, clientID)
		resp[KeyRoles] = roles
		resp[KeyPermissions] = perms
		resp[KeyMenus] = menus
	}
}

// validatePKCEForCode applies the RFC 7636 §4.3 PKCE rules for the
// authorization_code branch and returns the error code to reject with, or ""
// when the request passes. Defaults an empty method to "plain" (mutating req).
// Rules: PKCE is mandatory when the client requires it OR OAuth 2.1 strict mode
// is on; a supplied code_challenge must have a valid length + method; and a
// per-client method allowlist (when set) is enforced.
func validatePKCEForCode(req *login.Request, client *Client, oauth21Strict bool) string {
	if req.CodeChallenge == "" {
		if client.RequirePKCE || oauth21Strict {
			return ErrPKCERequired
		}
		return ""
	}
	if l := len(req.CodeChallenge); l < PKCEVerifierMinLen || l > PKCEVerifierMaxLen {
		return ErrInvalidRequest
	}
	if !isValidPKCEMethod(req.CodeChallengeMethod) {
		return ErrInvalidPKCEMethod
	}
	if req.CodeChallengeMethod == "" {
		req.CodeChallengeMethod = PKCEMethodPlain
	}
	// OAuth 2.1 §7.6 requires S256. An omitted method (defaulted to "plain")
	// and an explicit "plain" are both rejected when strict mode is on.
	if oauth21Strict && req.CodeChallengeMethod != PKCEMethodS256 {
		return ErrInvalidPKCEMethod
	}
	// Per-client PKCE method allowlist (Client.AllowedPKCEMethods): when set,
	// every challenge method MUST appear in the list — the canonical use case is
	// forcing S256 on production clients while leaving legacy clients on the
	// default (RFC-permissive) behavior.
	if !isPKCEMethodAllowedForClient(req.CodeChallengeMethod, client.AllowedPKCEMethods) {
		return ErrInvalidPKCEMethod
	}
	return ""
}

// finishLoginCodeFlow handles the authorization_code response branch: validate
// redirect_uri + PKCE, issue the code, and render it (form_post / JARM / JSON).
// Extracted verbatim from finishLogin to keep that orchestrator within the
// complexity budget; it owns the response in every path.
func (s *Server) finishLoginCodeFlow(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client) {
	state := req.State
	if s.authCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, s.authzErrorBodyWithState(ctx, ErrAuthCodeNotConfigured, state))
		return
	}
	// redirect_uri must be registered; OAuth 2.1 §4.1.3 additionally requires
	// https (localhost exempted for dev) under strict mode.
	if req.RedirectURI == "" || !client.IsRedirectURIValid(req.RedirectURI) ||
		(s.oauth21Strict && !isSecureRedirectURI(req.RedirectURI)) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRedirectURI)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRedirectURI, state))
		return
	}
	if code := validatePKCEForCode(req, client, s.oauth21Strict); code != "" {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, code)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, code, state))
		return
	}
	code, err := s.issueAuthCode(ctx.Request().Context(), result, req, client)
	if err != nil {
		s.logger.Error("failed to issue auth code", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrInternal, state))
		return
	}
	s.recordLoginSuccess(ctx, client.ID, req.Provider, "code", result.UserID, "")
	s.renderAuthCodeResponse(ctx, req, client, code)
}

// renderAuthCodeResponse writes the authorization_code result in the negotiated
// response mode: OIDC form_post (auto-POST HTML), JARM (signed JWT response), or
// the default JSON body. The caller has already issued the code and recorded
// success; a JARM signing failure fails closed with invalid_request rather than
// leaking the bare code under the shared key.
func (s *Server) renderAuthCodeResponse(ctx HandlerContext, req *login.Request, client *Client, code string) {
	if req.ResponseMode == ResponseModeFormPost {
		s.renderFormPostResponse(ctx, req.RedirectURI, code, req.State)
		return
	}
	if oidc.IsJARMResponseMode(req.ResponseMode) {
		signer, ok := s.jarmSignerForClient(client)
		if !ok || !oidc.RenderJARMResponse(ctx, signer, req.ResponseMode, req.RedirectURI, s.resolveIssuer(ctx), client.ID, code, req.State) {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, req.State))
		}
		return
	}
	resp := map[string]any{
		KeyCode: code,
		KeyIss:  s.resolveIssuer(ctx),
	}
	if req.State != "" {
		resp[KeyState] = req.State
	}
	ctx.JSON(http.StatusOK, resp)
}
