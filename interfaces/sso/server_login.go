package sso

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/protocols/fapi"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

func (s *Server) handleLogin(ctx HandlerContext) {
	req, ok := s.bootstrapLoginRequest(ctx)
	if !ok {
		return
	}

	// OIDC Core §3.1.2.1 prompt=none silent-renewal contract; parsed before the
	// providers/credential paths so this branch can override them (see handlePromptNone).
	prompts := oidc.ParsePromptValues(req.Prompt)
	if oidc.PromptHasNone(prompts) {
		s.handlePromptNone(ctx, prompts, &req)
		return
	}

	// No provider selected yet: home-realm discovery (B2B) or generic provider list.
	if s.respondLoginProviders(ctx, &req) {
		return
	}

	// Pre-authentication client gates (existence/active/tenant/residency/PAR-JAR-required/allowlist).
	client, handled := s.resolveAndValidateLoginClient(ctx, &req)
	if handled {
		return
	}

	// Post PAR+JAR-merge authz-request validation (order JAR -> FAPI -> param shapes).
	if s.runPostMergeAuthzValidation(ctx, &req, client) {
		return
	}

	// Resolve authenticator + validate credentials (federated redirect, lockout gate, verify).
	result, handled := s.authenticateUser(ctx, &req, client)
	if handled {
		return
	}

	// Post-credential gates (order ACR -> risk/step-up).
	if s.runPostCredentialGates(ctx, &req, result, client) {
		return
	}

	s.finishLogin(ctx, result, req, client)
}

// bootstrapLoginRequest performs the /auth/login prologue — identical in
// behavior and ORDER to the original inline opening — and returns the bound
// request plus ok=false the instant a guard wrote a response (the caller MUST
// return):
//
//   - Stamps the request start time onto the context for the
//     sso_login_duration_seconds histogram observed in recordLoginSuccess /
//     recordLoginFailure. That Login-specific histogram is separate from
//     sso_http_request_duration_seconds because it carries the provider label —
//     operators graphing "is the OIDC federation upstream slow" need the
//     per-provider slicing the bounded HTTP histogram doesn't provide.
//   - RFC 6749 §5.1: stamps Cache-Control: no-store + Pragma: no-cache, because
//     /auth/login bodies carry access_token + refresh_token (and PKCE-flow code
//     values) an intermediary cache must not retain.
//   - Binds the request body; a bind error writes 400 invalid_request.
//   - RFC 9126 §4: when request_uri is present, fetches the pushed authorization
//     parameters and merges them in (PAR holds AUTHORIZATION-SHAPED params —
//     response_type, redirect_uri, scope; credentials still arrive on THIS
//     request, so PAR can't bypass user authentication). The merge gives PAR
//     priority over caller-supplied so a tampered redirect can't override what
//     the client previously committed to. resolveLoginRequest writes the response
//     on a stale/missing request_uri.
func (s *Server) bootstrapLoginRequest(ctx HandlerContext) (login.Request, bool) {
	ctx.Set(ctxKeyLoginStart, time.Now())
	tokenNoStoreHeaders(ctx)
	var req login.Request
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, err.Error()))
		return req, false
	}
	if s.resolveLoginRequest(ctx, &req) {
		return req, false
	}
	return req, true
}

// runPostMergeAuthzValidation runs the authorization-request validation guards
// that must see the EFFECTIVE request, i.e. after the PAR and JAR merges have
// folded their parameters in. It returns true the instant an inner guard wrote a
// response, preserving the exact status+code and short-circuit ORDER of the
// original inline sequence (JAR apply -> FAPI baseline -> param shapes):
//
//   - RFC 9101 JAR: when the `request` parameter is present, the authorization
//     request parameters live inside a signed (optionally JWE-wrapped) JWT.
//     applyRequestObject verifies it against the client's JWKS and merges its
//     claims into req (JWT wins on conflict). Returns true (response written) on
//     a malformed/unverifiable request object.
//   - FAPI 2.0 Security Profile (§5.3.1) authorization-request baseline,
//     evaluated against the effective (post PAR+JAR merge) request. Inspection
//     mode audits and proceeds; enforce mode rejects (response written) on the
//     first violation.
//   - RFC 8707 resource allowlist + RFC 9396 authorization_details shape + OIDC
//     §5.5 claims-parameter shape — validated against the effective request.
func (s *Server) runPostMergeAuthzValidation(ctx HandlerContext, req *login.Request, client *Client) bool {
	if s.applyRequestObject(ctx, req, client) {
		return true
	}
	if s.enforceFAPIAuthorizationLogin(ctx, req) {
		return true
	}
	if s.validateLoginAuthorizationParams(ctx, req, client) {
		return true
	}
	return false
}

// runPostCredentialGates runs the gates that apply once credentials are
// validated. It returns true the instant an inner guard wrote a response,
// preserving the exact status+code and short-circuit ORDER of the original
// inline sequence (ACR -> max_age -> risk):
//
//   - OIDC §3.1.2.6 / §5.5.1.1 ACR enforcement (acr_values OR claims
//     id_token.acr), checked immediately after credential validation so it
//     applies regardless of a following MFA / risk decision.
//   - OIDC §3.1.2.6 max_age enforcement — satisfied by fresh credentials.
//   - Risk evaluation + step-up gate. Skipped entirely (zero overhead) when no
//     scorer configured; scorer errors fail OPEN by contract. Returns true when
//     it owns the response (risk-denied, or an MFA challenge was issued and the
//     client must follow up at /auth/mfa); false to proceed to finishLogin.
func (s *Server) runPostCredentialGates(ctx HandlerContext, req *login.Request, result *AuthResult, client *Client) bool {
	if s.enforceLoginACR(ctx, req, result) {
		return true
	}
	if s.enforceLoginMaxAge(ctx, req, result) {
		return true
	}
	if s.evaluateLoginRisk(ctx, result, req, client) {
		return true
	}
	return false
}

// respondLoginProviders handles the no-provider-selected case: home-realm
// discovery (B2B, opt-in) when the login hint's email domain maps to an
// enterprise connection, else the generic provider list. Returns true (response
// written) when it handled the request; false when a provider IS selected and
// the caller should proceed. A build without WithConnectionStore is
// byte-identical (resolveHomeRealm returns ok=false).
func (s *Server) respondLoginProviders(ctx HandlerContext, req *login.Request) bool {
	if req.Provider != "" {
		return false
	}
	if conn, ok := s.resolveHomeRealm(ctx, req.LoginHint); ok {
		ctx.JSON(http.StatusOK, map[string]any{
			keyHRConnectionRequired: true,
			keyHRConnectionID:       conn.ID,
			keyHRType:               string(conn.Type),
			keyHRTenantID:           conn.TenantID,
			keyHRDisplayName:        conn.DisplayName,
			KeyIss:                  s.resolveIssuer(ctx),
		})
		return true
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyProviders: s.providersForClient(ctx, req.ClientID),
		KeyIss:       s.resolveIssuer(ctx),
	})
	return true
}

// validateLoginAuthorizationParams enforces the request-parameter shapes: RFC
// 8707 resource allowlist, OIDC §5.5 claims-parameter (must be a JSON object),
// and RFC 9396 authorization_details (JSON array of {type,...}, type-allowlisted
// when the client declares one). Empty allowlists disable enforcement (legacy
// compat). Returns true when it wrote an error response.
func (s *Server) validateLoginAuthorizationParams(ctx HandlerContext, req *login.Request, client *Client) bool {
	if !client.AreResourcesAllowed(req.Resource) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidTarget)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidTarget))
		return true
	}
	if len(req.Claims) > 0 {
		if err := oauth.ValidateClaimsParameter(req.Claims); err != nil {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, err.Error()))
			return true
		}
	}
	if _, err := oauth.ValidateAuthorizationDetails(req.AuthorizationDetails, client.AllowedAuthorizationDetailsTypes); err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, oauth.ErrInvalidAuthorizationDetails)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, oauth.ErrInvalidAuthorizationDetails, err.Error()))
		return true
	}
	return false
}

// authenticateUser resolves the authenticator and validates credentials: a
// federated authenticator with a LoginURL redirects (handled=true); otherwise
// the per-account lockout gate runs BEFORE the verifier (so a locked account
// can't drain the constant-time hash budget), the credential is verified, and
// lockout state is updated (a failure may lock; a success clears the counter
// before any risk decision). Returns (result, handled) — handled=true means a
// response was written (redirect or rejection). Ordering is unchanged from the
// inline form.
func (s *Server) authenticateUser(ctx HandlerContext, req *login.Request, client *Client) (*AuthResult, bool) {
	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnsupportedProvider))
		return nil, true
	}
	if loginURL := auth.LoginURL(req.State); loginURL != "" {
		ctx.Redirect(http.StatusFound, loginURL)
		return nil, true
	}
	lockKey := s.lockoutKey(auth, req.ClientID, req.Credential)
	if s.accountLockout != nil && lockKey != "" {
		if locked, until, _ := s.accountLockout.IsLocked(ctx.Request().Context(), lockKey); locked {
			s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
			ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAccountLocked))
			return nil, true
		}
	}
	result, err := auth.Authenticate(ctx.Request().Context(), &AuthRequest{
		Provider:        req.Provider,
		Credential:      req.Credential,
		ClientID:        req.ClientID,
		Scope:           req.Scope,
		State:           req.State,
		LoginHint:       req.LoginHint,
		ACRValues:       splitScope(req.ACRValues),
		UILocales:       splitScope(req.UILocales),
		RequestedClaims: oauth.CloneRawJSON(req.Claims),
	})
	if err != nil {
		s.handleAuthFailure(ctx, req, lockKey, err)
		return nil, true
	}
	if s.rejectDeactivatedUser(ctx, req, result.UserID) {
		return nil, true
	}
	// A single legit login resets the brute-force budget (before risk evaluation).
	if s.accountLockout != nil && lockKey != "" {
		_ = s.accountLockout.RegisterSuccess(ctx.Request().Context(), lockKey)
	}
	return result, false
}

// handleAuthFailure writes the authentication-failure response: it attributes the
// failure to per-account lockout (and emits account_locked when that trips)
// BEFORE the generic login_failure audit, then collapses to invalid_credentials.
func (s *Server) handleAuthFailure(ctx HandlerContext, req *login.Request, lockKey string, err error) {
	s.logErrorCtx(ctx, "authentication failed", "provider", req.Provider, "error", err)
	if s.accountLockout != nil && lockKey != "" {
		if locked, until, _ := s.accountLockout.RegisterFailure(ctx.Request().Context(), lockKey); locked {
			s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
			ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAccountLocked))
			return
		}
	}
	s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidCredentials)
	ctx.JSON(http.StatusUnauthorized, s.authzErrorBody(ctx, ErrInvalidCredentials))
}

// rejectDeactivatedUser enforces SCIM deprovisioning (RFC 7643 active=false):
// even with a correct credential, a deactivated account MUST NOT obtain tokens.
// Called AFTER credential verification, BEFORE any token/session side effect, so
// an IdP connector that PATCHed active=false actually revokes access. Collapses
// to account_locked (an unavailable account, not a credential oracle: the
// credential already verified). No UserProvider = no SCIM state = no-op; a
// not-found user (federated/first login) is treated active. Returns true (with a
// response written) when the login must be rejected.
func (s *Server) rejectDeactivatedUser(ctx HandlerContext, req *login.Request, userID string) bool {
	if s.userProvider == nil {
		return false
	}
	u, uerr := s.userProvider.GetByID(ctx.Request().Context(), userID)
	if uerr != nil || u.IsActive() {
		return false
	}
	s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrAccountLocked)
	ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAccountLocked))
	return true
}

// lockoutKey derives the per-account brute-force lockout key. An authenticator
// that implements LockoutKeyer reports its OWN canonical, normalized identity
// field — authoritative: a credential it declares unkeyable ("") skips the gate
// rather than falling back to the spoofable field precedence (which an attacker
// could defeat by injecting a higher-precedence field the authenticator ignores,
// or by varying case/whitespace). Authenticators without it use the generic
// security.LockoutKey precedence (correct when their identity field is the first
// present, e.g. password's username).
func (s *Server) lockoutKey(auth Authenticator, clientID string, cred map[string]string) string {
	if lk, ok := auth.(LockoutKeyer); ok {
		id := lk.LockoutIdentity(cred)
		if id == "" {
			return ""
		}
		return clientID + ":" + id
	}
	return security.LockoutKey(clientID, cred)
}

// enforceLoginACR applies OIDC §3.1.2.6 / §5.5.1.1 ACR enforcement: the RP may
// demand ACR values via acr_values OR the claims parameter's id_token.acr entry,
// honored with identical strictness. Empty union = no constraint; a present list
// with no matching AchievedACR fails with the spec error (oracle-safe — the
// achieved ACR is never revealed). Returns true when it wrote an error response.
func (s *Server) enforceLoginACR(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	acrList := splitScope(req.ACRValues)
	if len(req.Claims) > 0 {
		acrList = append(acrList, oauth.RequestedACRFromClaims(req.Claims)...)
	}
	if len(acrList) > 0 && !slices.Contains(acrList, result.AchievedACR) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrUnmetAuthReqs)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnmetAuthReqs))
		return true
	}
	return false
}

// enforceLoginMaxAge enforces OIDC Core §3.1.2.6 max_age. Fresh
// credentials always satisfy any max_age window (AuthTime=now).
func (s *Server) enforceLoginMaxAge(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	if req.MaxAge == nil {
		return false
	}
	// max_age=0 → require fresh auth (user provided credentials ✓).
	// max_age=N → auth must be within N seconds (AuthTime=now ✓).
	// Issuance path sets AuthTime = time.Now() in tokens.
	return false
}

// loginUsedPAR reports whether the authorization request was driven by a real
// RFC 9126 pushed authorization request, NOT an RFC 9101 JAR-by-reference
// request_uri. Both arrive in req.RequestURI (the PAR merge / JAR fetch leave it
// populated), but only a PAR reference carries the
// urn:ietf:params:oauth:request_uri: scheme — server-stored, single-use,
// replay-resistant. An https JAR request_uri is re-fetched fresh on every
// /auth/login and is NOT a PAR. The RequirePAR gate and FAPI's PAR-required rule
// MUST key off this prefix: keying off mere presence let a JAR-by-reference
// silently satisfy a PAR mandate and downgrade PAR's single-use guarantee.
func loginUsedPAR(req *login.Request) bool {
	return strings.HasPrefix(req.RequestURI, oauth.PARURIPrefix)
}

// resolveAndValidateLoginClient looks up the requesting client and runs the
// pre-authentication client gates: existence, active, tenant binding,
// data-residency write-gate, RFC 9126 RequirePAR, RFC 9101
// RequireSignedRequestObject, and the per-client authenticator allowlist.
// Returns the client and handled=true when it wrote an error response (the
// caller MUST return). RequirePAR distinguishes a real PAR reference from a JAR
// request_uri via loginUsedPAR (both populate req.RequestURI). Extracted from
// handleLogin to keep that orchestrator within the complexity budget.
func (s *Server) resolveAndValidateLoginClient(ctx HandlerContext, req *login.Request) (*Client, bool) {
	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMissingClientID))
		return nil, true
	}
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
		return nil, true
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidClient)
		ctx.JSON(http.StatusUnauthorized, s.authzErrorBody(ctx, ErrInvalidClient))
		return nil, true
	}
	if !client.Active {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInactiveClient)
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
		return nil, true
	}
	if !clientTenantOK(ctx, client) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrTenantMismatch)
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrTenantMismatch))
		return nil, true
	}
	if s.residencyGateLogin(ctx, req.ClientID, req.Provider, client.TenantID) {
		return nil, true
	}
	if client.RequirePAR && !loginUsedPAR(req) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, "client requires pushed authorization request"))
		return nil, true
	}
	if client.RequireSignedRequestObject && req.Request == "" {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, "client requires signed request object"))
		return nil, true
	}
	if !client.IsAuthenticatorAllowed(req.Provider) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrAuthenticatorNotAllowed)
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAuthenticatorNotAllowed))
		return nil, true
	}
	return client, false
}

// enforceFAPIAuthorizationLogin runs the FAPI 2.0 §5.3.1 authorization-request
// baseline against the effective (post PAR+JAR merge) request. Inspection mode
// audits each violation and returns false (proceed); enforce mode rejects on the
// first violation, writes the response, and returns true. Each rule's capability
// (PAR / JAR / S256 PKCE) must be independently wired AND sent for a client to
// pass. Extracted verbatim from handleLogin to keep that orchestrator within the
// complexity budget.
func (s *Server) enforceFAPIAuthorizationLogin(ctx HandlerContext, req *login.Request) bool {
	if !s.fapiValidator.Active() {
		return false
	}
	vs := s.fapiValidator.CheckAuthorization(fapi.AuthorizationContext{
		ClientID:            req.ClientID,
		ResponseType:        req.ResponseType,
		UsedPAR:             loginUsedPAR(req),
		SignedRequest:       req.Request != "",
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})
	if len(vs) == 0 {
		return false
	}
	mode := s.fapiValidator.Mode().String()
	for _, v := range vs {
		audit.RecordFAPIViolation(s.auditor, ctx, v.ClientID, v.RuleID, v.Detail, mode)
		if s.metrics != nil {
			s.metrics.FAPIViolationsTotal.WithLabelValues(v.RuleID, mode).Inc()
		}
	}
	if s.fapiValidator.Enforcing() {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, "fapi: "+vs[0].RuleID+": "+vs[0].Detail))
		return true
	}
	return false
}

// evaluateLoginRisk runs the configured RiskScorer after credential validation
// and applies its decision: Deny rejects the login, RequireMFA (with an MFA
// provider + challenge store wired) issues a step-up challenge. Returns true when
// it owns the response (denied or MFA challenge issued); false to proceed.
// Scorer errors and a nil assessment FAIL OPEN (logged, login proceeds) — failing
// closed on a misbehaving scorer would lock every user out. RequireMFA with no
// provider wired falls through to Allow (historical no-op). Extracted verbatim
// from handleLogin; the credential->risk->MFA ordering is unchanged (it runs at
// the same point the inline block did).
func (s *Server) evaluateLoginRisk(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client) bool {
	if s.riskScorer == nil {
		return false
	}
	var geoInfo *geo.GeoInfo
	if g, ok := GeoFromHandlerContext(ctx); ok {
		geoInfo = g
	}
	assessment, riskErr := s.riskScorer.Score(ctx.Request().Context(), &spi.RiskRequest{
		SubjectID: result.UserID,
		ClientID:  req.ClientID,
		Provider:  req.Provider,
		RemoteIP:  audit.ClientIP(ctx.Request()),
		UserAgent: ctx.Request().UserAgent(),
		Geo:       geoInfo,
		Timestamp: time.Now(),
	})
	switch {
	case riskErr != nil:
		s.logErrorCtx(ctx, "risk scorer failed", "error", riskErr, "user", result.UserID, "client", req.ClientID)
	case assessment == nil:
		// Defensive: a scorer that returns (nil, nil) is misbehaving.
		s.logger.Error("risk scorer returned nil assessment", "user", result.UserID, "client", req.ClientID)
	default:
		if s.metrics != nil {
			s.metrics.RiskDecisionsTotal.WithLabelValues(string(assessment.Decision)).Inc()
		}
		if assessment.Decision == spi.DecisionDeny {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrRiskDenied)
			ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrRiskDenied))
			return true
		}
		if assessment.Decision == spi.DecisionRequireMFA && s.mfaProvider != nil && s.mfaChallengeStore != nil {
			// Step-up gate engaged: persist the in-flight state and return
			// mfa_required so the client follows up at /auth/mfa. issueMFAChallenge
			// writes the response; resume happens in handleMFAComplete.
			s.issueMFAChallenge(ctx, result, *req, client)
			return true
		}
	}
	return false
}
