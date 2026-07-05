package sso

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/continuousverify"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/trust"
)

// stepUpTrustDescription is the RFC 6750 error_description on the RFC 9470
// step-up challenge the min-trust gate returns. Developer-facing only — SPAs
// MUST branch on the error CODE (insufficient_user_authentication), never this
// text (AGENTS.md: descriptions stay out of the auth decision).
const stepUpTrustDescription = "session trust below threshold; step-up required"

// SessionTrustDecayConfig configures the zero-trust session-trust-decay feature
// (WithSessionTrustDecay, Direction 3 Phase 3): a trust score bound to each
// session at login decays over time, a background ContinuousVerificationAgent
// marks below-floor sessions for step-up, and a min-trust gate
// (Server.RequireSessionTrust) challenges high-risk operations.
//
// The zero value leaves the feature OFF (Factor/Interval unset ⇒ decay
// disabled), so a Server built without this option is byte-identical to today.
type SessionTrustDecayConfig struct {
	// Interval + Factor define the exponential decay curve: the bound score is
	// multiplied by Factor (in the open range (0,1), e.g. 0.95) once per Interval
	// of elapsed time. Interval <= 0 or a Factor outside (0,1) disables the whole
	// feature (the fields are the enable switch).
	Interval time.Duration
	Factor   float64

	// Floor is the continuous-verification agent's step-up threshold: a live
	// session whose decayed score drops below Floor is marked for step-up.
	Floor float64

	// MinScore is the asymptotic lower bound the decayed score never falls below
	// (avoids decaying an old-but-legitimate session to a hard 0). Zero leaves the
	// natural exp-toward-0 curve.
	MinScore float64

	// SweepInterval is the agent's polling cadence (<=0 ⇒ the package default,
	// continuousverify.DefaultSweepInterval).
	SweepInterval time.Duration

	// StepUpACRValues / StepUpMaxAge shape the RFC 9470 step-up challenge the
	// min-trust gate returns below threshold. When both are empty the gate demands
	// a fresh re-authentication (a 1-second max_age window).
	StepUpACRValues []string
	StepUpMaxAge    int

	// InitialScore is the trust bound to a session at login (0 < v <= 1); any
	// value outside that range defaults to 1.0 — fully trusted at login, decaying
	// thereafter.
	InitialScore float64
}

// sessionTrustWiring is the resolved WithSessionTrustDecay state held on the
// Server (an unexported value so the public surface stays the flat config +
// option, mirroring capStore/capEngine).
type sessionTrustWiring struct {
	cfg          trust.DecayConfig
	sweep        time.Duration
	stepUpACR    []string
	stepUpMaxAge int
	initialScore float64
}

// enabled reports whether the feature is active (decay configured). The zero
// value is disabled, so every consumer (login stamping, the gate, the agent)
// short-circuits to byte-identical-off behavior.
func (w sessionTrustWiring) enabled() bool { return w.cfg.Enabled() }

// WithSessionTrustDecay wires the zero-trust session-trust-decay feature. A
// config whose decay curve is invalid/unset (Factor outside (0,1) or Interval
// <= 0) is a no-op — byte-identical to a build without the option. Start the
// background agent with Server.StartContinuousVerification under the process
// lifecycle; gate high-risk operations with Server.RequireSessionTrust.
func WithSessionTrustDecay(cfg SessionTrustDecayConfig) Option {
	return func(s *Server) {
		dc := trust.DecayConfig{
			Interval: cfg.Interval,
			Factor:   cfg.Factor,
			Floor:    cfg.Floor,
			MinScore: cfg.MinScore,
		}
		if !dc.Enabled() {
			return
		}
		init := cfg.InitialScore
		if init <= 0 || init > 1 {
			init = 1.0
		}
		s.sessionTrust = sessionTrustWiring{
			cfg:          dc,
			sweep:        cfg.SweepInterval,
			stepUpACR:    cfg.StepUpACRValues,
			stepUpMaxAge: cfg.StepUpMaxAge,
			initialScore: init,
		}
	}
}

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

// RequireSessionTrust is the zero-trust min-trust gate for a high-risk operation
// (an admin mutation, a self-service credential change): it challenges the caller
// for RFC 9470 step-up when the session identified by sessionID has a decayed
// trust below minTrust — or the ContinuousVerificationAgent already flagged it.
// It returns true when it OWNS the response (a 401 + WWW-Authenticate step-up
// challenge is written); false to proceed with the operation.
//
// FAIL-OPEN (spec Edge Cases): returns false (proceed) whenever the feature is
// off, the gate is disabled for this operation (minTrust <= 0), or the session
// can't be read (missing / store outage). The gate is advisory infra and MUST
// NOT lock a user out on absent scoring data — the enforcement floor stays the
// normal auth/session checks.
func (s *Server) RequireSessionTrust(ctx HandlerContext, sessionID string, minTrust float64) bool {
	if !s.sessionTrust.enabled() || minTrust <= 0 || sessionID == "" || s.sessionMgr == nil {
		return false
	}
	sess, err := s.sessionMgr.Get(ctx.Request().Context(), sessionID)
	if err != nil || sess == nil {
		return false
	}
	if !trust.StepUpRequiredForTrust(*sess, time.Now(), s.sessionTrust.cfg, minTrust) {
		return false
	}
	s.writeStepUpChallenge(ctx)
	return true
}

// writeStepUpChallenge stamps the RFC 9470 WWW-Authenticate step-up challenge
// (built from the configured acr_values / max_age demand) plus no-store headers
// and a 401 with the oracle-safe generic insufficient_user_authentication body.
// When neither demand is configured it falls back to a 1-second max_age window —
// an effectively-immediate re-authentication demand (RFC 9470 has no semantics
// for a challenge that demands nothing).
func (s *Server) writeStepUpChallenge(ctx HandlerContext) {
	challenge := security.StepUpChallenge{
		ACRValues:   s.sessionTrust.stepUpACR,
		MaxAge:      s.sessionTrust.stepUpMaxAge,
		Realm:       s.resolveIssuer(ctx),
		Description: stepUpTrustDescription,
	}
	if len(challenge.ACRValues) == 0 && challenge.MaxAge == 0 {
		challenge.MaxAge = 1
	}
	tokenNoStoreHeaders(ctx)
	if header, err := security.BuildStepUpChallenge(challenge); err == nil {
		ctx.ResponseWriter().Header().Set("WWW-Authenticate", header)
	}
	ctx.JSON(http.StatusUnauthorized, errorBody(security.ErrInsufficientUserAuthentication))
}

// StartContinuousVerification launches the zero-trust ContinuousVerificationAgent
// (Direction 3 Phase 3) — a background loop that periodically decays live
// sessions' trust and marks below-floor ones for step-up. The returned channel
// closes when the loop exits; cancel ctx to stop it (mirrors
// StartSigningKeyAggregation). Inert (returns a closed channel) when the feature
// is off or the wired SessionManager can't persist the step-up flag
// (SessionTrustManager), so the caller may invoke it unconditionally.
func (s *Server) StartContinuousVerification(ctx context.Context) <-chan struct{} {
	marker, _ := s.sessionMgr.(SessionTrustManager)
	if !s.sessionTrust.enabled() || s.sessionMgr == nil || marker == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	opts := []continuousverify.Option{
		continuousverify.WithMetrics(s.metrics),
		continuousverify.WithLogger(s.logger),
		continuousverify.WithEventHook(func(e continuousverify.Event) {
			audit.RecordSessionTrustStepUp(s.auditor, context.Background(), e.SessionID, e.UserID, e.Score, e.Floor)
		}),
	}
	if s.sessionTrust.sweep > 0 {
		opts = append(opts, continuousverify.WithSweepInterval(s.sessionTrust.sweep))
	}
	agent := continuousverify.NewAgent(s.sessionMgr, marker, s.sessionTrust.cfg, opts...)
	return agent.Start(ctx)
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
	// Scope-count cap — a byte-length-bounded scope string can still carry
	// an excessive NUMBER of short scope tokens; <= 0 (default) is
	// unbounded, same as before this gate existed.
	if max := s.maxScopeCount; max > 0 && len(req.Scope) > max {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidScope)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrInvalidScope, req.State))
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
	if _, err := oauth.ValidateAuthorizationDetails(req.AuthorizationDetails, client.AllowedAuthorizationDetailsTypes, s.rarLimits); err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, oauth.ErrInvalidAuthorizationDetails)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, oauth.ErrInvalidAuthorizationDetails, req.State))
		return true
	}
	return false
}

// RARLimits returns the configured RFC 9396 authorization_details shape
// caps (depth/size/element-count). Also satisfies oauth.PARDeps so
// HandlePAR enforces the SAME limits as /auth/login.
func (s *Server) RARLimits() oauth.RARLimits { return s.rarLimits }

// MaxScopeCount returns the configured cap on the number of space-separated
// scopes accepted in a single request's `scope` parameter; <= 0 (default)
// means unbounded. Also satisfies oauth.PARDeps.
func (s *Server) MaxScopeCount() int { return s.maxScopeCount }

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
