package sso

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/protocols/fapi"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
	"github.com/snaplink/sso/shared/trust"
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

// enforceConditionalAccessLogin is the LIVE Policy Enforcement Point: called
// from runPostCredentialGates (server_login_gates.go) after credential
// validation but BEFORE token/session issuance, it builds the request's
// trust signals (the wired trust.TrustScorer composite score +
// DeviceFingerprint lookup) and acts on the engine's Decision. A complete
// no-op — zero signal collection, zero engine call — unless BOTH a store is
// wired (WithConditionalAccess) AND its Config.Enforce is true, so a
// deployment that only wants the advisory EvaluateConditionalAccess /
// admin-view behavior (Enforce left false, the default) sees byte-identical
// /auth/login behavior.
//
// Fail-open contract (AGENTS.md "Fail Modes"): the trust scorer and the
// engine's policy store are both risk SIGNALS, not credential checks. Either
// one erroring (an unreachable data source) is logged and the login
// PROCEEDS — never denied — so an attacker cannot starve/poison a signal
// source into a mass account-lockout oracle. Only a verdict the engine
// computed from data it successfully read is ever acted on:
//   - VerdictDeny blocks the login (403 conditional_access_denied).
//   - VerdictRequireStepUp reuses the EXISTING RiskScorer step-up mechanism
//     (WithMFAProvider + WithMFAChallengeStore) rather than inventing a
//     parallel one: without both wired, it decays to allow — the same
//     historical no-op RiskScorer's RequireMFA falls back to.
//   - VerdictAllow (including the engine's own no-policy-matched default)
//     proceeds.
//
// Returns true when it owns the response (denied, or an MFA challenge was
// issued and the client must follow up at /auth/mfa); false to proceed.
func (s *Server) enforceConditionalAccessLogin(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client) bool {
	if s.capEngine == nil || !s.capEngine.Config().Enforce {
		return false
	}
	reqCtx := ctx.Request().Context()
	dec, err := s.capEngine.Evaluate(reqCtx, s.buildAccessContext(ctx, result, req, client))
	if err != nil {
		// Data-source outage: fail OPEN regardless of the engine's own
		// configured default verdict (Config.DefaultDeny governs the advisory
		// EvaluateConditionalAccess path, not this live gate) — a poisoned or
		// unreachable signal source must never become an account-lockout lever.
		s.logger.Error("conditional access policy store unavailable; failing open", "error", err, "user", result.UserID, "client", req.ClientID)
		return false
	}
	if s.metrics != nil {
		s.metrics.ObserveConditionalAccessDecision(string(dec.Verdict))
	}
	switch dec.Verdict {
	case conditionalaccess.VerdictDeny:
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrConditionalAccessDenied)
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrConditionalAccessDenied, req.State))
		return true
	case conditionalaccess.VerdictRequireStepUp:
		if s.mfaProvider != nil && s.mfaChallengeStore != nil {
			s.issueMFAChallenge(ctx, result, *req, client)
			return true
		}
	}
	return false
}

// buildAccessContext assembles the conditional-access engine's per-request
// AccessContext: the wired trust.TrustScorer composite score (degrading to
// "unknown" on error or when unwired) and the DeviceFingerprint posture
// lookup (degrading to PostureUnknown identically). Groups is left
// unpopulated — no group/role-membership signal source is wired into the
// login path this wave, so a user.member_of policy condition simply never
// matches (Conditions.specificity treats an empty condition as
// unconstrained, never as a deny).
func (s *Server) buildAccessContext(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client) conditionalaccess.AccessContext {
	signals := s.buildTrustSignals(ctx, result, client)
	ac := conditionalaccess.AccessContext{
		DevicePosture:   s.lookupDevicePosture(ctx, signals),
		Country:         signals.Geo.CountryCode,
		Now:             time.Now(),
		RequestedScopes: req.Scope,
		Subject:         result.UserID,
		ClientID:        client.ID,
	}
	if s.trustScorer == nil {
		return ac
	}
	score, err := s.trustScorer.Score(ctx.Request().Context(), signals)
	if err != nil {
		// Fail-open on the data source: leave TrustScoreKnown false so the
		// engine substitutes its own conservative degraded-trust floor
		// (Config.DegradedTrust) instead of this gate manufacturing a value.
		s.logger.Error("trust scorer failed; conditional access falls back to the degraded-trust floor", "error", err, "user", result.UserID)
		return ac
	}
	ac.TrustScore = score.Value
	ac.TrustScoreKnown = true
	return ac
}

// buildTrustSignals captures the request-time trust.TrustSignals available at
// /auth/login: remote IP, geo (when the geo middleware ran), subject/client,
// the live AMR/ACR this authentication achieved, and whatever device hints
// the caller sent (User-Agent + the opaque X-Device-Id fingerprint header).
func (s *Server) buildTrustSignals(ctx HandlerContext, result *AuthResult, client *Client) trust.TrustSignals {
	var geoInfo core.GeoInfo
	if g, ok := GeoFromHandlerContext(ctx); ok && g != nil {
		geoInfo = *g
	}
	hints := make(map[string]string, 2)
	if ua := ctx.Request().UserAgent(); ua != "" {
		hints[trustHintUserAgent] = ua
	}
	if fp := deviceFingerprintFromRequest(ctx); fp != "" {
		hints[trustHintDeviceID] = fp
	}
	return trust.TrustSignals{
		RemoteIP:    audit.ClientIP(ctx.Request()),
		Geo:         geoInfo,
		UserID:      result.UserID,
		ClientID:    client.ID,
		Time:        time.Now(),
		AMR:         result.AuthMethods,
		ACR:         result.AchievedACR,
		DeviceHints: hints,
	}
}

// trustHintUserAgent / trustHintDeviceID key the free-form
// trust.TrustSignals.DeviceHints map this login wiring populates.
const (
	trustHintUserAgent = "user_agent"
	trustHintDeviceID  = "device_id"
)

// deviceFingerprintFromRequest reads the caller-supplied opaque device
// fingerprint. Never derived from the User-Agent alone — that header is
// shared by every user on the same browser/OS build, so using it as a
// device-identity KEY would misattribute one device's posture to another;
// an absent header means "no fingerprint offered", not "unknown device
// posture manufactured from a coarse hint".
func deviceFingerprintFromRequest(ctx HandlerContext) string {
	return ctx.Request().Header.Get(core.HeaderDeviceID)
}

// lookupDevicePosture resolves the wired DeviceFingerprint's posture for this
// request. Nil provider, an absent fingerprint, a lookup miss, and a lookup
// ERROR all degrade identically to PostureUnknown — the engine's existing
// conservative default for a device that never reports (fail-open on the
// data source; a lookup outage must never read as "confirmed unmanaged").
func (s *Server) lookupDevicePosture(ctx HandlerContext, signals trust.TrustSignals) conditionalaccess.DevicePosture {
	if s.deviceFingerprint == nil {
		return conditionalaccess.PostureUnknown
	}
	fp := signals.DeviceHints[trustHintDeviceID]
	if fp == "" {
		return conditionalaccess.PostureUnknown
	}
	posture, ok, err := s.deviceFingerprint.Lookup(ctx.Request().Context(), fp)
	if err != nil {
		s.logger.Error("device fingerprint lookup failed; degrading to unknown posture", "error", err)
		return conditionalaccess.PostureUnknown
	}
	if !ok {
		return conditionalaccess.PostureUnknown
	}
	return posture
}
