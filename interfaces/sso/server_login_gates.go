package sso

import (
	"context"
	"net/http"
	"strings"

	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// EvaluateConditionalAccess resolves the wired zero-trust conditional-access
// policies against ac and returns the advisory Decision. It is the SDK entry
// point for callers that want a CAP decision (an external PEP, a gateway, an
// embedding app's own gate).
//
// ADVISORY this wave: the Server deliberately does NOT call this from its live
// /auth/login control flow (see runPostCredentialGates) — the PEP integration
// is a later phase. When WithConditionalAccess is not wired the engine is nil
// and this returns a permissive allow, so a caller can invoke it
// unconditionally.
//
// A policy-store outage does not deny every request: the engine falls back to
// the configured default verdict (fail-closed only if the operator set
// Config.DefaultDeny) and the error is logged here.
func (s *Server) EvaluateConditionalAccess(ctx context.Context, ac AccessContext) ConditionalAccessDecision {
	if s.capEngine == nil {
		return ConditionalAccessDecision{Verdict: conditionalaccess.VerdictAllow}
	}
	dec, err := s.capEngine.Evaluate(ctx, ac)
	if err != nil {
		s.logger.Error("conditional access policy store unavailable", "error", err)
	}
	s.metrics.ObserveConditionalAccessDecision(string(dec.Verdict))
	return dec
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
// inline sequence (ACR -> max_age -> risk -> email-verification):
//
//   - OIDC §3.1.2.6 / §5.5.1.1 ACR enforcement (acr_values OR claims
//     id_token.acr), checked immediately after credential validation so it
//     applies regardless of a following MFA / risk decision.
//   - OIDC §3.1.2.6 max_age enforcement — satisfied by fresh credentials.
//   - Risk evaluation + step-up gate. Skipped entirely (zero overhead) when no
//     scorer configured; scorer errors fail OPEN by contract. Returns true when
//     it owns the response (risk-denied, or an MFA challenge was issued and the
//     client must follow up at /auth/mfa); false to proceed to finishLogin.
//   - Email-verification gate — only active when WithSignupRequireVerification is
//     set. Runs AFTER credential validation (oracle-safe: attacker who knows the
//     password cannot distinguish "no such user" from "unverified").
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
	if s.rejectUnverifiedEmail(ctx, req, result) {
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

// validateLoginAuthorizationParams enforces the request-parameter shapes:
// parameter length limits (DoS prevention), RFC 8707 resource allowlist,
// OIDC §5.5 claims-parameter (must be a JSON object), and RFC 9396
// authorization_details (JSON array of {type,...}, type-allowlisted when
// the client declares one). Empty allowlists disable enforcement (legacy
// compat). Returns true when it wrote an error response.
func (s *Server) validateLoginAuthorizationParams(ctx HandlerContext, req *login.Request, client *Client) bool {
	// Parameter length limits — prevent DoS via oversized params that
	// would bloat AuthCode store entries and amplify redirect responses.
	// Scope is joined with spaces to match the wire format length.
	if code := oauth.CheckAuthParamLengths(
		req.State, req.RedirectURI, strings.Join(req.Scope, " "), req.Nonce, req.Resource,
	); code != "" {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidRequest)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrInvalidRequest, req.State))
		return true
	}
	if !client.AreResourcesAllowed(req.Resource) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidTarget)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrInvalidTarget, req.State))
		return true
	}
	if len(req.Claims) > 0 {
		if err := oauth.ValidateClaimsParameter(req.Claims); err != nil {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidRequest)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrInvalidRequest, req.State))
			return true
		}
	}
	if _, err := oauth.ValidateAuthorizationDetails(req.AuthorizationDetails, client.AllowedAuthorizationDetailsTypes); err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, oauth.ErrInvalidAuthorizationDetails)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, oauth.ErrInvalidAuthorizationDetails, req.State))
		return true
	}
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

// checkLoginDeadline checks whether the request context has exceeded its
// deadline (set by WithAuthorizeRequestTimeout). When it has, it writes an
// interaction_required error response and returns true so the caller returns.
// Returns false when the context is still valid (proceed).
func (s *Server) checkLoginDeadline(ctx HandlerContext, state string) bool {
	if err := ctx.Request().Context().Err(); err != nil {
		ctx.JSON(http.StatusGatewayTimeout, s.authzErrorBodyWithState(ctx, core.ErrInteractionRequired, state))
		return true
	}
	return false
}
