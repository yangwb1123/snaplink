package sso

import (
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/internal/handler"
	"net/http"
	"slices"
	"time"

	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/region"
)

// matter whether MFA gated the request or not.
func (s *Server) finishLogin(ctx HandlerContext, result *AuthResult, req login.Request, client *Client) {
	if s.userProvider != nil {
		user := &User{
			ID:         result.UserID,
			ExternalID: result.ExternalID,
			Provider:   result.Provider,
			Attributes: result.Attributes,
		}
		if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
			s.logger.Error("failed to upsert user", "error", err)
			ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
			return
		}
	}

	// Non-blocking credential-health signal. Emitted once here so it
	// covers every downstream branch (code flow + direct mint) and both
	// the primary login and the MFA-resumed re-entry, which all funnel
	// through finishLogin. The signal NEVER blocks login and NEVER rides
	// on the wire or into any token — AuthResult.CredentialHealth is
	// json:"-", so generic serialization (tokens, the MFA challenge store)
	// strips it; the MFA step-up path re-threads it explicitly via
	// mfaResumeState.CredentialHealth so this audit still fires after
	// resume. It lands only in the audit log. nil = no signal (healthy
	// credential or no checker wired).
	s.recordCredentialHealth(ctx, client.ID, result.UserID, result.CredentialHealth)

	// OAuth 2.1 strict mode: response_type=token (implicit) is
	// retired by OAuth 2.1; empty response_type (which defaulted
	// to direct-mint in OAuth 2.0) is treated the same way under
	// strict mode. Both reject with unsupported_response_type
	// — strict mode requires explicit response_type=code.
	if s.oauth21Strict && req.ResponseType != "code" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnsupportedResponseType))
		return
	}

	// OIDC Form Post Response Mode 1.0 — validate response_mode
	// early so a bad value fails BEFORE any side-effects (auth code
	// issue, session create). Empty is always valid and falls
	// through to the response_type's default mode.
	if req.ResponseMode != "" && !s.isValidResponseMode(req.ResponseMode) {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequest))
		return
	}

	// Scope authorization (RFC 6749 §3.3) — the access-control gate on
	// what the issued token may carry. Run here, AFTER authentication and
	// the tenant/residency gates, so it can never be a pre-auth probe and
	// covers BOTH the authorization_code branch (the granted set is baked
	// into the stored code) and the direct-mint branch below. Mirrors the
	// tenant_mismatch / residency gates: record the failure + emit the
	// authz error body carrying the RFC 9207 iss. req.Scope is replaced
	// with the GRANTED set (validated, or defaulted to the client's
	// AllowedScopes when the request named no scope) so every downstream
	// consumer — auth code, direct mint, refresh, id_token gate — sees
	// the authorized scope. Empty allowlist = unrestricted = req.Scope
	// passes through unchanged (byte-identical for clients without one).
	granted, scopeErr := oauth.GrantedScopes(req.Scope, client)
	if scopeErr != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidScope)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidScope))
		return
	}
	req.Scope = granted

	// Consent gate (opt-in via WithConsentStore, nil = no-op).
	// Runs AFTER scope authorization so req.Scope is the granted set that
	// will actually appear in the issued token — the grant we check and
	// record is authoritative for exactly those scopes.
	if s.consentStore != nil {
		if s.handleConsentGate(ctx, result.UserID, client, req.Scope, req.Prompt, req.ConsentChallengeID) {
			return
		}
	}

	// JIT org-membership provisioning (opt-in): a user logging in through a
	// tenant-bound client who isn't yet on that org's roster is auto-added as a
	// member, so federated users appear in their org without manual invitation.
	// Fail-open + best-effort — never blocks login.
	s.ensureJITMembership(ctx, client, result.UserID)

	// OAuth 2.0 authorization_code branch: instead of minting a token
	// here, persist a short-lived code bound to (user, client, redirect_uri)
	// and return it so the relying party can exchange it via /token.
	if req.ResponseType == "code" {
		if s.authCodeStore == nil {
			ctx.JSON(http.StatusNotImplemented, s.authzErrorBody(ctx, ErrAuthCodeNotConfigured))
			return
		}
		if req.RedirectURI == "" || !client.IsRedirectURIValid(req.RedirectURI) {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRedirectURI)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRedirectURI))
			return
		}
		// OAuth 2.1 §4.1.3 — redirect_uri MUST use https. Localhost
		// (any port) remains permitted for development workflows.
		if s.oauth21Strict && !isSecureRedirectURI(req.RedirectURI) {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRedirectURI)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRedirectURI))
			return
		}
		// PKCE validation per RFC 7636 §4.3:
		// * If client policy requires PKCE, code_challenge MUST be set.
		// * OAuth 2.1 §4.1.1 makes PKCE mandatory; strict mode honors
		//   that even when the client has RequirePKCE=false set.
		// * If code_challenge IS set, length and method MUST be valid.
		// * Empty method defaults to "plain" per §4.3 (callers should
		//   prefer S256; "plain" stays for legacy interop).
		if req.CodeChallenge == "" {
			if client.RequirePKCE || s.oauth21Strict {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrPKCERequired)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrPKCERequired))
				return
			}
		} else {
			if l := len(req.CodeChallenge); l < PKCEVerifierMinLen || l > PKCEVerifierMaxLen {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequest))
				return
			}
			if !isValidPKCEMethod(req.CodeChallengeMethod) {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidPKCEMethod)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidPKCEMethod))
				return
			}
			if req.CodeChallengeMethod == "" {
				req.CodeChallengeMethod = PKCEMethodPlain
			}
			// Per-client PKCE method allowlist (Client.AllowedPKCEMethods).
			// When set, every challenge method MUST appear in the list
			// — the canonical use case is forcing S256 on production
			// clients while leaving legacy clients on the default
			// (RFC-permissive) behavior.
			if !isPKCEMethodAllowedForClient(req.CodeChallengeMethod, client.AllowedPKCEMethods) {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidPKCEMethod)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidPKCEMethod))
				return
			}
		}
		code, err := s.issueAuthCode(ctx.Request().Context(), result, &req, client)
		if err != nil {
			s.logger.Error("failed to issue auth code", "error", err)
			ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
			return
		}
		s.recordLoginSuccess(ctx, client.ID, req.Provider, "code", result.UserID, "")

		// OIDC Form Post Response Mode 1.0: when the RP requested
		// form_post, render an HTML auto-POST page targeting
		// redirect_uri instead of the JSON body. Available only on
		// code flow (where there's a redirect_uri to POST to);
		// other response modes (query, fragment, empty) keep the
		// existing JSON response — the RP's own JS handles the
		// post-fetch redirect.
		if req.ResponseMode == ResponseModeFormPost {
			s.renderFormPostResponse(ctx, req.RedirectURI, code, req.State)
			return
		}

		// JARM — sign the authorization response into a JWT carried as
		// the single `response` parameter (query / fragment / form_post
		// per the sub-mode; the bare `jwt` alias resolves to query). A
		// JARM mode only reaches here when a signer is wired (gated in
		// isValidResponseMode). The signer is resolved per-tenant so a
		// tenant's authorization response is signed by the same key as
		// its access + id tokens. A signing failure — or a tenant whose
		// issuer can't sign JARM (jarmSignerForClient → ok=false) —
		// fails closed with invalid_request rather than leaking the bare
		// code under the shared key.
		if oidc.IsJARMResponseMode(req.ResponseMode) {
			signer, ok := s.jarmSignerForClient(client)
			if !ok || !oidc.RenderJARMResponse(ctx, signer, req.ResponseMode, req.RedirectURI, s.resolveIssuer(ctx), client.ID, code, req.State) {
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequest))
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
		return
	}
	if req.ResponseType != "" && req.ResponseType != "token" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnsupportedResponseType))
		return
	}

	if s.sessionMgr == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrSessionMgrNotConfigured))
		return
	}
	session, err := s.createSession(ctx, result.UserID, client.TenantID)
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		s.logger.Error("no token strategy for client", "client", client.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrNoTokenStrategy))
		return
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
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	s.recordLoginSuccess(ctx, client.ID, req.Provider, strategy, result.UserID, session.ID)
	s.recordSubjectClientAccess(ctx.Request().Context(), result.UserID, client.ID)

	// Geo enrichment: if the authenticator didn't supply
	// country/language hints, fall back to whatever the geo
	// middleware stashed on the request. Authenticators with a
	// stronger signal (SIM region, account default, explicit user
	// pref) override the geo guess by setting them themselves.
	// One Get to avoid two ctx.Get round trips.
	if result.CountryCode == "" || result.RecommendedLanguage == "" {
		if info, ok := GeoFromHandlerContext(ctx); ok {
			if result.CountryCode == "" {
				result.CountryCode = info.CountryCode
			}
			if result.RecommendedLanguage == "" {
				result.RecommendedLanguage = info.RecommendedLanguage
			}
		}
	}

	// When a oauth.RefreshTokenStore is wired, server-managed refresh tokens
	// override whatever the underlying TokenIssuer returned — that way
	// the OAuth refresh_token grant works uniformly regardless of which
	// issuer minted the access token. Fail-open: a refresh-token store
	// outage doesn't block the login (user gets an access_token they
	// can use until expiry), but it does surface as a server-side
	// logger.Error so operators see the degradation.
	refreshTokenOut := token.RefreshToken
	if s.refreshTokenStore != nil {
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			result.UserID, client.ID, result.Provider, req.Scope, result.Attributes, "", req.Resource,
			req.AuthorizationDetails, session.ID, client.RefreshTokenTTL)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err, "client", client.ID, "user", result.UserID)
		} else {
			refreshTokenOut = rt
			s.recordRefreshTokenIssued(ctx, client.ID, result.UserID, false)
		}
	}

	resp := map[string]any{
		KeySessionID:     session.ID,
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyRefreshToken:  refreshTokenOut,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
		KeyIss:           s.resolveIssuer(ctx),
	}
	// Native SSO 1.0: when the client was granted the device_sso scope and a
	// device-secret store is wired, mint a device_secret BEFORE the id_token so
	// its ds_hash can ride the id_token. Fail-open: issuance failure logs and
	// omits the secret (the access_token is already minted).
	var deviceSecretValue string
	if slices.Contains(req.Scope, ScopeDeviceSSO) && s.deviceSecretStore != nil {
		if ds, dsErr := s.issueDeviceSecret(ctx.Request().Context(), result.UserID, session.ID, client.ID); dsErr != nil {
			s.logger.Error("device secret issue failed", "error", dsErr, "client", client.ID, "user", result.UserID)
		} else {
			deviceSecretValue = ds
		}
	}
	// OIDC ID Token: emit alongside the access token whenever the
	// caller requested "openid" scope AND an issuer is wired. Errors
	// fail open — a misconfigured ID-token issuer shouldn't block the
	// underlying authentication, the relying party just won't get
	// id_token in the response.
	if slices.Contains(req.Scope, ScopeOpenID) {
		idIssuer, emit, idErr := s.idTokenIssuerForClient(client)
		if idErr != nil {
			// Tenant mapping named an unregistered issuer — fail closed
			// (omit id_token) rather than sign with the shared key.
			s.logger.Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID, "user", result.UserID)
		} else if emit {
			// OIDC Core §5.5 — the id_token carries the resolved user
			// attribute set. The claims-parameter id_token.acr request is
			// enforced upstream (folded into ACR enforcement after credential
			// validation), so it is not re-projected here; requested claims
			// that the AS cannot source from Attributes are a no-op (we can't
			// invent values).
			idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:      issuedSub,
				Audience:     client.ID,
				Nonce:        req.Nonce,
				AuthTime:     time.Now(),
				AMR:          handler.AmrForResult(result),
				ACR:          result.AchievedACR,
				Claims:       result.Attributes,
				SID:          session.ID,
				AccessToken:  token.AccessToken,
				DeviceSecret: deviceSecretValue,
			})
			if err != nil {
				s.logger.Error("id token issue failed", "error", err, "client", client.ID, "user", result.UserID)
			} else if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
				resp[KeyIDToken] = enc
				s.recordIDTokenIssued(ctx, client.ID, result.UserID)
			}
		}
	}
	if deviceSecretValue != "" {
		resp[KeyDeviceSecret] = deviceSecretValue
	}
	if result.CountryCode != "" {
		resp[KeyCountryCode] = result.CountryCode
	}
	if result.RecommendedLanguage != "" {
		resp[KeyRecommendedLang] = result.RecommendedLanguage
	}
	// serving_region surfaces WHICH regional deployment served this login —
	// a UX/governance hint for the SPA, not a security signal. Only present
	// when the region middleware resolved a non-empty region (no resolver
	// wired → absent → response shape byte-identical to a pre-region build).
	if servingRegion, ok := region.FromHandlerContext(ctx); ok && servingRegion != "" {
		resp[KeyServingRegion] = string(servingRegion)
	}
	if s.embedPermissions {
		roles, perms, menus := s.resolvePermissionsForLogin(ctx.Request().Context(), result.UserID, client.ID)
		resp[KeyRoles] = roles
		resp[KeyPermissions] = perms
		resp[KeyMenus] = menus
	}
	ctx.JSON(http.StatusOK, resp)
}

// issueAuthCode generates an authorization code, persists it against the
// store, and returns the opaque code string. The TTL is taken from the
