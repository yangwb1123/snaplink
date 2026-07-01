package sso

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/protocols/fapi"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

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
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrMissingClientID, req.State))
		return nil, true
	}
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, core.ErrClientStoreNotConfigured, req.State))
		return nil, true
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidClient)
		ctx.JSON(http.StatusUnauthorized, s.authzErrorBodyWithState(ctx, core.ErrInvalidClient, req.State))
		return nil, true
	}
	if !client.Active {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInactiveClient)
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrInactiveClient, req.State))
		return nil, true
	}
	if !clientTenantOK(ctx, client) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrTenantMismatch)
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrTenantMismatch, req.State))
		return nil, true
	}
	if s.residencyGateLogin(ctx, req.ClientID, req.Provider, client.TenantID) {
		return nil, true
	}
	if client.RequirePAR && !loginUsedPAR(req) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidRequest)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrInvalidRequest, req.State))
		return nil, true
	}
	if client.RequireSignedRequestObject && req.Request == "" {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidRequest)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrInvalidRequest, req.State))
		return nil, true
	}
	if !client.IsAuthenticatorAllowed(req.Provider) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrAuthenticatorNotAllowed)
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrAuthenticatorNotAllowed, req.State))
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
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidRequest)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrInvalidRequest, req.State))
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
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrRiskDenied)
			ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrRiskDenied, req.State))
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
