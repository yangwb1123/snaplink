package sso

import (
	"encoding/json"
	"net/http"
	"time"
)

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
	if _, err := validateAuthorizationDetails(req.AuthorizationDetails, client.AllowedAuthorizationDetailsTypes); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(ErrInvalidAuthorizationDetails, err.Error()))
		return
	}

	ttl := s.parTTL
	if ttl <= 0 {
		ttl = DefaultPARTTL
	}
	uri, err := s.parStore.Issue(ctx.Request().Context(), &PARRequest{
		ClientID:             req.ClientID,
		ResponseType:         req.ResponseType,
		RedirectURI:          req.RedirectURI,
		Scope:                splitScope(req.Scope),
		State:                req.State,
		Nonce:                req.Nonce,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resource:             req.Resource,
		AuthorizationDetails: cloneRawJSON(req.AuthorizationDetails),
		LoginHint:            req.LoginHint,
		ResponseMode:         req.ResponseMode,
		ACRValues:            req.ACRValues,
		UILocales:            req.UILocales,
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
