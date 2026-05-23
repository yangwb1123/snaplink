package sso

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/security"
)

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
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		Token               string `json:"token"`
		TokenTypeHint       string `json:"token_type_hint"` // "access_token" | "refresh_token"
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
		// HTTP Basic auth takes precedence over body fields when present
		// — matches the RFC 6749 §2.3.1 recommendation.
		req.ClientID = id
		req.ClientSecret = secret
	}

	// RFC 7521/7523 JWT bearer client auth on /token/introspect.
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
		// Bypass the secret-based authenticate path entirely: JWT
		// assertion stands in for the secret per RFC 7521 §4.2.
		// Still validate the tenant + active gates below via a
		// minimal client lookup so a deactivated client can't
		// introspect.
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
	}
	// RFC 9068 §2.2 supplies a first-class `client_id` claim. Prefer
	// it; fall back to the first audience entry for older tokens or
	// non-RFC-9068 issuers (per RFC 7662 §2.2 the field is optional).
	switch {
	case claims.ClientID != "":
		body[KeyClientID] = claims.ClientID
	case len(claims.Audience) > 0:
		body[KeyClientID] = claims.Audience[0]
	}
	if len(claims.Scopes) > 0 {
		body[KeyScope] = strings.Join(claims.Scopes, " ")
	}
	// RFC 9068 §2.2 jti — useful for replay tracking on the
	// introspecting resource server. Same goes for auth_time / acr
	// / amr which let downstream policy reason about how the user
	// authenticated.
	if claims.JTI != "" {
		body[KeyJTI] = claims.JTI
	}
	if !claims.AuthTime.IsZero() {
		body[KeyAuthTime] = claims.AuthTime.Unix()
	}
	if claims.ACR != "" {
		body[KeyACR] = claims.ACR
	}
	if len(claims.AMR) > 0 {
		body[KeyAMR] = claims.AMR
	}
	return body, true
}

// introspectRefresh queries the optional oauth.RefreshTokenInspector. Returns
// (nil, false) when the store doesn't implement the inspector
// extension OR the token is unknown / expired.
func (s *Server) introspectRefresh(ctx HandlerContext, token string) (map[string]any, bool) {
	insp, ok := s.refreshTokenStore.(oauth.RefreshTokenInspector)
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

// handlePAR implements RFC 9126 Pushed Authorization Requests.
// Confidential clients POST their authorization request parameters
// here BEFORE redirecting the user agent, getting back an opaque
// request_uri they then pass to /auth/login. This pre-registration
// pattern:
//
//   - Authenticates the client BEFORE the user-agent redirect (the
//     traditional authorization flow has the AS see the client
//     only AFTER the redirect, when there's nothing to do about a
//     bad request beyond rendering an error).
//   - Removes long auth-request URLs (PKCE + scopes + state +
//     resource + nonce add up fast) that browsers, log files, and
//     proxies all handle poorly.
//   - Prevents request-tampering: nothing in the redirect URL
//     beyond client_id + request_uri can be modified without
//     invalidating the lookup.
//
// Auth: HTTP Basic OR client_id+client_secret form body per
// RFC 6749 §2.3.1 (Basic wins when both present — same precedence
// rule as /token).
//
// Spec sentinel mapping:
//   - missing client credentials              → 401 invalid_client
//   - PAR store not wired                     → 501 par_not_configured
//   - invalid redirect_uri allowlist          → 400 invalid_redirect_uri
//   - resource not in allowlist (RFC 8707)    → 400 invalid_target
//
// Response per RFC 9126 §2.2:
//
//	{
//	  "request_uri": "urn:ietf:params:oauth:request_uri:<token>",
//	  "expires_in":  90
//	}
func (s *Server) handlePAR(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	if s.parStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrPARNotConfigured))
		return
	}
	if err := s.requireDeps(depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		ClientID             string          `json:"client_id"`
		ClientSecret         string          `json:"client_secret"`
		ResponseType         string          `json:"response_type"`
		RedirectURI          string          `json:"redirect_uri"`
		Scope                string          `json:"scope"`
		State                string          `json:"state"`
		Nonce                string          `json:"nonce"`
		CodeChallenge        string          `json:"code_challenge"`
		CodeChallengeMethod  string          `json:"code_challenge_method"`
		Resource             []string        `json:"resource"`
		AuthorizationDetails json.RawMessage `json:"authorization_details"` // RFC 9396
		LoginHint            string          `json:"login_hint"`            // OIDC Core §3.1.2.1
		ResponseMode         string          `json:"response_mode"`         // OIDC Form Post 1.0
		ACRValues            string          `json:"acr_values"`            // OIDC Core §3.1.2.1
		UILocales            string          `json:"ui_locales"`            // OIDC Core §3.1.2.1
		Claims               json.RawMessage `json:"claims"`                // OIDC Core §5.5
		ClientAssertion      string          `json:"client_assertion"`      // RFC 7521 + 7523
		ClientAssertionType  string          `json:"client_assertion_type"` // RFC 7521 + 7523
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if id, secret, ok := basicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
	}

	// RFC 7521/7523 — JWT bearer client authentication is accepted
	// on /par just like /token. When the assertion is supplied, the
	// JWT's `sub` claim is the authoritative client identity (form
	// `client_id` MUST agree if supplied at all).
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
	}

	if req.ClientID == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingClientID))
		return
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}
	if !client.Active {
		ctx.JSON(http.StatusForbidden, errorBody(ErrInactiveClient))
		return
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ErrTenantMismatch))
		return
	}
	// Skip client_secret validation when the JWT assertion already
	// proved client identity (RFC 7521 §4.2 forbids requiring both).
	if req.ClientAssertion == "" {
		if err := s.clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClientSecret))
			return
		}
	}
	if req.RedirectURI != "" && !client.IsRedirectURIValid(req.RedirectURI) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRedirectURI))
		return
	}
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return
	}
	// OIDC Form Post 1.0: reject malformed response_mode at PAR
	// time so the caller fails fast (whole point of PAR — surface
	// validation upstream of the user-agent redirect).
	if req.ResponseMode != "" && !isValidResponseMode(req.ResponseMode) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	// RFC 9396: validate authorization_details up front so a
	// malformed / disallowed payload fails at PAR time rather than
	// surfacing later at /auth/login (PAR's whole point is to move
	// validation upstream of the user-agent redirect).
	if _, err := oauth.ValidateAuthorizationDetails(req.AuthorizationDetails, client.AllowedAuthorizationDetailsTypes); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(oauth.ErrInvalidAuthorizationDetails, err.Error()))
		return
	}

	ttl := s.parTTL
	if ttl <= 0 {
		ttl = oauth.DefaultPARTTL
	}
	uri, err := s.parStore.Issue(ctx.Request().Context(), &oauth.PARRequest{
		ClientID:             req.ClientID,
		ResponseType:         req.ResponseType,
		RedirectURI:          req.RedirectURI,
		Scope:                splitScope(req.Scope),
		State:                req.State,
		Nonce:                req.Nonce,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resource:             req.Resource,
		AuthorizationDetails: oauth.CloneRawJSON(req.AuthorizationDetails),
		LoginHint:            req.LoginHint,
		ResponseMode:         req.ResponseMode,
		ACRValues:            req.ACRValues,
		UILocales:            req.UILocales,
		Claims:               oauth.CloneRawJSON(req.Claims),
		ExpiresAt:            time.Now().Add(ttl),
	})
	if err != nil {
		s.logger.Error("par issue failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	ctx.JSON(http.StatusCreated, map[string]any{
		"request_uri": uri,
		"expires_in":  int(ttl.Seconds()),
	})
}

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
	revoked, failed := s.revokeAcrossIssuers(ctx.Request().Context(), token)
	s.auditPartialRevokeFailure(ctx, revoked, failed)
}

// revokeRefresh deletes via the optional oauth.RefreshTokenInspector.Delete
// extension. No-op when the store doesn't implement the extension —
// callers in that situation must rely on TTL expiry.
func (s *Server) revokeRefresh(ctx HandlerContext, token string) {
	insp, ok := s.refreshTokenStore.(oauth.RefreshTokenInspector)
	if !ok {
		return
	}
	_ = insp.Delete(ctx.Request().Context(), token)
}

// handleRevokeAll implements the "logout everywhere" endpoint. The
// user presents a bearer token; the server reads sub + aud from its
// claims, then kills every refresh token bound to that
// (subject, client) pair via the optional oauth.RefreshTokenSubjectIndex
// extension. The presented access token is also revoked via the
// normal per-issuer path so it stops working immediately.
//
// Useful for a "sign out of all devices" button — one round trip
// instead of per-device per-token revocation.
//
// Requires the oauth.RefreshTokenStore to implement
// oauth.RefreshTokenSubjectIndex; without it, the response is 501.
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
	idx, ok := s.refreshTokenStore.(oauth.RefreshTokenSubjectIndex)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrRefreshTokenNotConfigured))
		return
	}

	bearer := bearerToken(ctx.Request())
	if bearer == "" {
		setBearerChallenge(ctx, s.resolveIssuer(ctx), "", "")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer)
	if err != nil || claims == nil || claims.Subject == "" {
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "The access token is invalid or expired")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}

	// OIDC §8 pairwise: refresh tokens are stored by local sub.
	// Translate pairwise → local before the bulk delete so the
	// caller's revoke-all actually finds anything.
	lookupSub, perr := s.resolveLocalSubject(ctx.Request().Context(), claims.Subject)
	if perr != nil {
		s.logger.Error("pairwise resolve failed at revoke-all", "error", perr, "subject", claims.Subject)
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Subject mapping unavailable")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}
	deleted, err := idx.DeleteAllForSubject(ctx.Request().Context(), lookupSub, clientID)
	if err != nil {
		s.logger.Error("revoke-all failed", "error", err, "subject", lookupSub)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// Also revoke the presented access token across all issuers so it
	// stops working immediately — without this, the bearer the caller
	// just used would keep working until expiry, which is surprising
	// for a "logout everywhere" semantic.
	revoked, failed := s.revokeAcrossIssuers(ctx.Request().Context(), bearer)
	s.auditPartialRevokeFailure(ctx, revoked, failed)

	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:                StatusOK,
		"refresh_tokens_revoked": deleted,
	})
}

// handleTokenExchangeGrant implements RFC 8693 OAuth 2.0 Token
// Exchange. The grant lets one party swap an existing token for
// another — typically a downstream service exchanging the user's
// access token for a token scoped specifically to its callee, so
// the original token isn't replayed across services (the "confused
// deputy" defense that resource indicators (RFC 8707) is also
// designed for).
//
// Request (form-encoded per RFC 6749 §3.2):
//
//   - grant_type            urn:ietf:params:oauth:grant-type:token-exchange
//   - subject_token         REQUIRED — the token being exchanged
//   - subject_token_type    REQUIRED — token type URI
//   - resource              RFC 8707 audience (zero or more)
//   - audience              RFC 8693 audience (zero or more)
//   - scope                 OPTIONAL — narrow the issued token's scope
//   - requested_token_type  OPTIONAL — defaults to access_token
//   - actor_token /
//     actor_token_type      OPTIONAL — for delegation chains
//
// Response per §2.2.1:
//
//	{
//	  "access_token":      "<new token>",
//	  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
//	  "token_type":        "Bearer",
//	  "expires_in":        N,
//	  "scope":             "...",
//	  "token_strategy":    "<wired strategy name>"
//	}
//
// v1 supports:
//   - Subject token type access_token (the common case — exchange a
//     bearer for a more narrowly-audienced bearer).
//   - Requested token type access_token (default) and refresh_token
//     (when WithRefreshTokenStore is wired — opts in the family
//     rotation + RFC 8693 §2.2 issued_token_type=refresh_token
//     response shape).
//   - resource + audience (merged into the new token's aud claim).
//   - Scope narrowing (subset of the subject token's scopes).
//   - actor_token replay protection via WithJTIReplayStore.
//
// Future-scope (deliberately deferred for v1):
//   - JWT / SAML subject tokens (requires bespoke validators).
//   - Actor token delegation chain in the issued token's claims.
//
// Sentinel mapping:
//
//   - missing subject_token / subject_token_type → 400 invalid_request
//   - unsupported subject_token_type → 400 invalid_request
//   - subject_token failed validation → 400 invalid_grant
//   - unregistered resource / audience → 400 invalid_target (RFC 8707)
//   - scope expansion attempt → 400 invalid_scope (RFC 6749 §6 analogue)
//   - unsupported requested_token_type → 400 invalid_request
func (s *Server) handleTokenExchangeGrant(ctx HandlerContext, client *Client, req tokenExchangeRequest) {
	if req.SubjectToken == "" || req.SubjectTokenType == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if req.SubjectTokenType != TokenTypeAccessToken &&
		req.SubjectTokenType != TokenTypeJWT {
		// RFC 8693 §2.1 lists more token types; v1 only handles
		// signed access tokens issued by this server.
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if req.RequestedTokenType != "" &&
		req.RequestedTokenType != TokenTypeAccessToken &&
		req.RequestedTokenType != TokenTypeRefreshToken {
		// Access + Refresh supported; ID token / SAML2 are future
		// work (no compelling caller need yet). Anything else =>
		// caller wanted something we can't deliver.
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	// Refresh-token output requires a wired refresh store — without
	// it there's no way to honor the resulting rotation grant. Fail
	// fast rather than silently downgrade to access-only.
	if req.RequestedTokenType == TokenTypeRefreshToken && s.refreshTokenStore == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrRefreshTokenNotConfigured))
		return
	}

	claims, _, err := s.validateAnyToken(ctx.Request().Context(), req.SubjectToken)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	// RFC 9470 step-up: when the caller demands a minimum ACR via
	// `acr_values`, the inbound subject_token's ACR claim MUST match
	// at least one value in the demand set. Otherwise the AS would
	// have to re-authenticate the user, which token-exchange
	// (server-to-server) can't do — caller must instead route the
	// user through /auth/login with the same acr_values. Same wire
	// shape as the resource-server challenge (insufficient_user_authentication)
	// so SPAs branch on it uniformly across grants.
	if req.ACRValues != "" {
		demanded := strings.Fields(req.ACRValues)
		if !acrMatchesAny(claims.ACR, demanded) {
			ctx.JSON(http.StatusBadRequest, errorBody(security.ErrInsufficientUserAuthentication))
			return
		}
	}

	// RFC 8693 §2.1: actor_token and actor_token_type MUST both
	// be present, or both absent. Mismatch = invalid_request.
	if (req.ActorToken == "") != (req.ActorTokenType == "") {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	var actor *ActorClaim
	if req.ActorToken != "" {
		if req.ActorTokenType != TokenTypeAccessToken && req.ActorTokenType != TokenTypeJWT {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		actorClaims, _, aerr := s.validateAnyToken(ctx.Request().Context(), req.ActorToken)
		if aerr != nil || actorClaims == nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Defense-in-depth: when a security.JTIReplayStore is wired AND the
		// actor_token carries a `jti`, refuse to honor the same
		// delegation assertion twice within its expiry window. The
		// actor_token is a short-lived delegation proof — replay
		// would let a captured proof be re-used to mint new
		// downstream tokens after the legitimate exchange already
		// happened. Mirrors the same defense JAR + DPoP +
		// client_assertion already opt into; namespace prevents
		// collision with those jti spaces. Empty jti / no store /
		// store error all fall through (RFC 8693 doesn't mandate
		// the check; collapse to invalid_grant on confirmed reuse).
		if s.jtiReplayStore != nil && actorClaims.JTI != "" {
			expiry := actorClaims.ExpiresAt
			if expiry.IsZero() {
				expiry = time.Now().Add(security.DefaultJTIReplayWindow)
			}
			first, rerr := s.jtiReplayStore.MarkSeen(ctx.Request().Context(), "tokex-act:"+actorClaims.JTI, expiry)
			if rerr == nil && !first {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
				return
			}
		}
		// RFC 8693 §4.1.1: when the subject_token already carries
		// an `act` claim (it was itself a delegated token), the
		// new act prepends the current actor and nests the
		// previous chain beneath, preserving full provenance.
		// Reading outside-in walks the delegation chain in
		// time-order: outermost is most recent.
		actor = &ActorClaim{Subject: actorClaims.Subject, Actor: claims.Actor}
	}

	// Merge `resource` + `audience` into the new token's aud claim.
	// Both parameter forms are accepted (RFC 8693 + RFC 8707
	// overlap on intent); deduplicated in-order so the first
	// occurrence wins for deterministic output.
	resources := mergeTargets(req.Resource, req.Audience)
	if !client.AreResourcesAllowed(resources) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return
	}

	// Scope narrowing per RFC 8693 §2.1: when `scope` is supplied
	// it MUST be a subset of the subject_token's scopes; expansion
	// is forbidden. Empty scope = keep the subject's scopes.
	scopes := claims.Scopes
	if req.Scope != "" {
		requested := strings.Split(req.Scope, " ")
		if !isScopeSubset(requested, claims.Scopes) {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidScope))
			return
		}
		scopes = requested
	}

	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}

	// Carry the subject identity through. The new token's `sub` is
	// the same as the subject_token's — token exchange does NOT
	// change the principal, only the audience / scope. ClientID is
	// the requesting (downstream) client, NOT the original; that's
	// the canonical RFC 8693 semantic ("on behalf of the same
	// subject, scoped to me").
	// OIDC §8 pairwise: the inbound subject_token's `sub` may be
	// pairwise (issued for the originating client's sector); resolve to
	// the local sub, then re-apply pairwise for the new (downstream)
	// client's sector. The exchange does not change the principal but
	// the wire sub differs whenever the downstream client lives in a
	// different sector. Non-pairwise deployments are a no-op pair.
	localSub, perr := s.resolveLocalSubject(ctx.Request().Context(), claims.Subject)
	if perr != nil {
		s.logger.Error("pairwise resolve failed at token-exchange", "error", perr, "subject", claims.Subject)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, localSub)
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:        issuedSub,
		Claims:    claims.Extra,
		Resources: resources,
		ClientID:  client.ID,
		// auth_time + amr propagate from the original subject_token
		// — the exchange doesn't represent a fresh end-user auth
		// event; carrying the originals lets downstream services
		// see the actual factor strength.
		AuthTime: claims.AuthTime,
		ACR:      claims.ACR,
		AMR:      append([]string(nil), claims.AMR...),
		// RFC 8693 §4.1 — when an actor_token is presented, the
		// new token carries `act: {sub: <actor.sub>}` so
		// downstream services can audit who acted on behalf of
		// whom. Nil when no actor_token was supplied (the direct
		// non-delegated path).
		Actor: actor,
		TTL:   client.AccessTokenTTL,
		// RFC 9396: preserve the subject_token's authorization_details
		// across the exchange so the resulting token carries the
		// same fine-grained authorization the user originally
		// consented to. The downstream service relying on RAR
		// shouldn't lose its binding just because a token was
		// exchanged into a narrower audience.
		AuthorizationDetails: oauth.CloneRawJSON(claims.AuthorizationDetails),
	}, scopes)
	if err != nil {
		s.logger.Error("token exchange issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordTokenIssued(ctx, client.ID, strategy, claims.Subject)
	s.recordSubjectClientAccess(ctx.Request().Context(), claims.Subject, client.ID)

	resp := map[string]any{
		KeyAccessToken:     token.AccessToken,
		KeyIssuedTokenType: TokenTypeAccessToken,
		KeyTokenType:       token.TokenType,
		KeyExpiresIn:       token.ExpiresIn,
		KeyScope:           token.Scope,
		KeyTokenStrategy:   strategy,
	}
	// RFC 8693 §2.1: when requested_token_type is refresh_token,
	// mint a refresh token alongside (the access token is always
	// returned — the spec uses requested_token_type to name what
	// the `issued_token_type` field reports back, not what's
	// emitted exclusively). Provider/AMR/Resources/AuthDetails/SID
	// propagate from the subject_token's claims so a rotated
	// chain inherits the same authorization context.
	if req.RequestedTokenType == TokenTypeRefreshToken && s.refreshTokenStore != nil {
		provider := ""
		if len(claims.AMR) > 0 {
			provider = claims.AMR[0]
		}
		rt, rerr := s.issueRefreshToken(
			ctx.Request().Context(),
			claims.Subject, client.ID, provider,
			scopes, claims.Extra, "", resources,
			oauth.CloneRawJSON(claims.AuthorizationDetails), // RFC 9396 — propagate the inbound binding
			claims.SID,
			client.RefreshTokenTTL,
		)
		if rerr != nil {
			s.logger.Error("token exchange refresh issue failed", "strategy", strategy, "error", rerr)
			// Fail-open: caller still gets the access token. Spec
			// allows this since the access token alone is a complete
			// response; the refresh is a bonus capability the caller
			// can re-request.
		} else {
			resp[KeyRefreshToken] = rt
			resp[KeyIssuedTokenType] = TokenTypeRefreshToken
			s.recordRefreshTokenIssued(ctx, client.ID, claims.Subject, false)
		}
	}

	ctx.JSON(http.StatusOK, resp)
}

// tokenExchangeRequest is the subset of /token parameters the
// token-exchange grant cares about. Pulled out of the main /token
// request struct so the switch branch reads cleanly.
type tokenExchangeRequest struct {
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
	Resource           []string
	Audience           []string
	Scope              string
	RequestedTokenType string
	// RFC 9470 step-up: caller-asserted ACR floor for the exchanged
	// token. Space-separated values; the inbound subject_token's
	// ACR claim MUST be a member of this set or the exchange fails
	// with insufficient_user_authentication. Empty = no demand
	// (inbound ACR transparently propagates as today).
	ACRValues string
}

// acrMatchesAny reports whether the inbound ACR claim matches any of
// the demanded values. Empty inbound ACR never matches any non-empty
// demand — a subject token with no factor information can't satisfy
// a step-up gate.
func acrMatchesAny(inbound string, demanded []string) bool {
	if inbound == "" || len(demanded) == 0 {
		return false
	}
	return slices.Contains(demanded, inbound)
}

// mergeTargets deduplicates a slice of resource / audience URIs
// while preserving the first-occurrence order. Both RFC 8707
// `resource` and RFC 8693 `audience` express the same intent;
// merging lets callers use whichever vocabulary their tooling
// favors without changing the token contents.
func mergeTargets(primary, secondary []string) []string {
	if len(primary) == 0 && len(secondary) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(primary)+len(secondary))
	out := make([]string, 0, len(primary)+len(secondary))
	for _, s := range primary {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range secondary {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
