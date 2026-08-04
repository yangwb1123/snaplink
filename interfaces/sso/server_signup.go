package sso

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/internal/handler"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/selfservice"
	"github.com/yangwb1123/snaplink/protocols/selfservice/selfservicecore"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// The DCR endpoint always has a conservative, per-IP storage-abuse guard.
const (
	defaultClientRegistrationRatePerSec = 5.0 / 60
	defaultClientRegistrationRateBurst  = 5
)

func (s *Server) handleRegister(ctx HandlerContext) {
	if !s.checkClientRegistrationRateLimit(ctx) {
		oauth.HandleRegister(s, ctx)
	}
}

// checkClientRegistrationRateLimit is separate from the opt-in global rate
// policy because an unthrottled registration endpoint is a storage-exhaustion
// vector. It uses the trusted-proxies-aware canonical client IP.
func (s *Server) checkClientRegistrationRateLimit(ctx HandlerContext) bool {
	lim := s.clientRegistrationRateLimiter
	if lim == nil {
		return false
	}
	ok, retryAfter := lim.Allow(ratelimit.KeyByClientIP(ctx.Request()))
	if ok {
		return false
	}
	middleware.TokenNoStoreHeaders(ctx)
	if retryAfter > 0 {
		seconds := max(1, int(math.Ceil(retryAfter.Seconds())))
		ctx.ResponseWriter().Header().Set(ratelimit.HeaderRetryAfter, strconv.Itoa(seconds))
	}
	ctx.JSON(http.StatusTooManyRequests, errorBody(ctx, ratelimit.ErrRateLimited))
	return true
}

// handleSelfRegister delegates to selfservice.HandleSelfRegister.
func (s *Server) handleSelfRegister(ctx HandlerContext) {
	selfservice.HandleSelfRegister(s, ctx)
}

// handleVerifyEmail delegates to selfservice.HandleVerifyEmail.
func (s *Server) handleVerifyEmail(ctx HandlerContext) {
	selfservice.HandleVerifyEmail(s, ctx)
}

// Deps interface implementation for selfservice.Deps

// UserProvider returns the user provider.
func (s *Server) UserProvider() UserProvider {
	return s.userProvider
}

// PasswordCredentialStore returns the password credential store.
func (s *Server) PasswordCredentialStore() PasswordCredentialStore {
	return s.passwordCredentialStore
}

// EmailChangeStore returns the email change store.
func (s *Server) EmailChangeStore() EmailChangeStore {
	return s.emailChangeStore
}

// PasswordResetStore returns the password reset store.
func (s *Server) PasswordResetStore() PasswordResetStore {
	return s.passwordResetStore
}

// EmailChangeTTL returns the email change token TTL.
func (s *Server) EmailChangeTTL() time.Duration {
	return s.emailChangeTTL
}

// PasswordResetTTL returns the password reset token TTL.
func (s *Server) PasswordResetTTL() time.Duration {
	return s.passwordResetTTL
}

// PasswordResetResolver returns the password reset resolver function.
func (s *Server) PasswordResetResolver() func(ctx context.Context, identifier string) (string, error) {
	return s.passwordResetResolver
}

// PasswordResetDeliveryResolver returns the password reset delivery resolver function.
func (s *Server) PasswordResetDeliveryResolver() func(ctx context.Context, userID string) (string, error) {
	return s.passwordResetDeliveryResolver
}

// ShutdownAuthenticatorDelivery drains optional asynchronous OTP/magic-link
// transports before their CodeStore or network dependencies are closed.
func (s *Server) ShutdownAuthenticatorDelivery(ctx context.Context) error {
	var failures []error
	for _, authenticator := range s.authenticators {
		closer, ok := authenticator.(interface{ CloseCodeDelivery(context.Context) error })
		if ok {
			failures = append(failures, closer.CloseCodeDelivery(ctx))
		}
	}
	return errors.Join(failures...)
}

// PasswordResetSender returns the password reset sender.
func (s *Server) PasswordResetSender() spi.PasswordResetSender {
	return s.passwordResetSender
}

// SessionManager returns the session manager.
func (s *Server) SessionManager() SessionManager {
	return s.sessionMgr
}

// Logger returns the logger.
func (s *Server) Logger() spi.Logger {
	return s.logger
}

// GenerateAuthCodeBytes delegates to oauth.GenerateAuthCodeBytes.
func (s *Server) GenerateAuthCodeBytes() (string, error) {
	return generateAuthCodeBytes()
}

// TokenNoStoreHeaders sets no-store headers.
func (s *Server) TokenNoStoreHeaders(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
}

// resolvedSecurityHeadersPolicy returns the operator-supplied CSP/Permissions-
// Policy override (WithSecurityHeadersPolicy), or the zero value when unset —
// handler.SecurityHeaders resolves a zero-value field to
// handler.DefaultSecurityHeadersPolicy itself, so callers never need to.
func (s *Server) resolvedSecurityHeadersPolicy() handler.SecurityHeadersPolicy {
	if s.securityHeadersPolicy != nil {
		return *s.securityHeadersPolicy
	}
	return handler.SecurityHeadersPolicy{}
}

// wrapSecurityHeaders applies the security-headers middleware (CSP +
// Permissions-Policy + per-request nonce + the existing default-deny headers)
// to h when WithSecurityHeaders/WithSecurityHeadersPolicy is wired. Used for
// the opt-in SPA bundles (admin console, hosted login, portal), which are
// served OUTSIDE the SSO router's own middleware chain (buildProbeMux) and so
// need this applied explicitly. No-op (returns h unchanged) when the feature
// is off — byte-identical to a build without it.
func (s *Server) wrapSecurityHeaders(h http.Handler) http.Handler {
	if !s.securityHeadersEnabled {
		return h
	}
	return handler.SecurityHeaders(s.resolvedSecurityHeadersPolicy())(h)
}

// ClearSiteData sets the Clear-Site-Data response header — instructing the
// browser to purge cache/cookies/storage for this origin — when security
// headers are enabled (WithSecurityHeaders / WithSecurityHeadersPolicy).
// Callers use this ONLY on a DEFINITIVE end to the session on this origin
// (POST /logout, POST /me/account/erase when not a dry run) — never on a
// per-token revoke, which may leave other sessions/tabs on this origin
// alive. No-op (byte-identical) when security headers are not enabled.
func (s *Server) ClearSiteData(ctx HandlerContext) {
	if !s.securityHeadersEnabled {
		return
	}
	middleware.ClearSiteData(ctx)
}

// ErrorBody creates an error response body.
//
// selfservicecore.Deps.ErrorBody has no HandlerContext parameter (it
// predates trace-id enrichment and is called from ~85 sites across
// protocols/selfservice), so unlike errorBody/authzErrorBody it can't
// look up the request's trace ID — it stays on the plain envelope.
// Widening the Deps interface to thread ctx through is out of scope
// here; see errorBody (interfaces/sso/handlers.go) and authzErrorBody
// (server_discovery.go) for the trace-id-enriched equivalents.
func (s *Server) ErrorBody(errCode string) map[string]any {
	result := make(map[string]any)
	for k, v := range core.ErrorBody(errCode) {
		result[k] = v
	}
	return result
}

func (s *Server) ErrorBodyDesc(errCode, desc string) map[string]any {
	result := make(map[string]any)
	for k, v := range core.ErrorBodyDesc(errCode, desc) {
		result[k] = v
	}
	return result
}

// handleMyEmailChange delegates to selfservice.HandleMyEmailChange.
func (s *Server) handleMyEmailChange(ctx HandlerContext) {
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	selfservice.HandleMyEmailChange(s, ctx, userID)
}

// handleMyEmailVerify delegates to selfservice.HandleMyEmailVerify.
func (s *Server) handleMyEmailVerify(ctx HandlerContext) {
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	selfservice.HandleMyEmailVerify(s, ctx, userID)
}

// EmailChangeSender returns the email change sender.
func (s *Server) EmailChangeSender() spi.EmailChangeSender {
	return s.emailChangeSender
}

// EmailVerificationStore returns the email verification store.
func (s *Server) EmailVerificationStore() core.EmailVerificationStore {
	return s.emailVerificationStore
}

// EmailVerificationSender returns the email verification sender.
func (s *Server) EmailVerificationSender() spi.EmailVerificationSender {
	return s.emailVerificationSender
}

// SignupRequiresVerification returns whether mandatory email verification is
// enabled for self-service signup.
func (s *Server) SignupRequiresVerification() bool {
	return s.signupRequireVerification
}

// RegistrationGates returns the wired registration abuse-protection gates.
func (s *Server) RegistrationGates() []spi.RegistrationGate {
	return s.registrationGates
}

// SignupRateLimiter returns the optional per-IP rate limiter for self-service
// signup (WithSelfServiceSignupRateLimiter). Nil means no signup-specific
// rate limiting — full backward compatibility.
func (s *Server) SignupRateLimiter() selfservicecore.RateLimiter {
	return s.signupRateLimiter
}

// EmailVerificationTTL returns the email verification token TTL.
func (s *Server) EmailVerificationTTL() time.Duration {
	return s.emailVerificationTTL
}

// PasswordPolicyValidator returns the wired password policy validator, or nil
// if no policy is enforced.
func (s *Server) PasswordPolicyValidator() spi.PasswordPolicyValidator {
	return s.passwordPolicyValidator
}

// WithPasswordPolicy wires a password policy validator that checks proposed
// passwords against operator-configured complexity rules. When nil (the
// default), no policy is enforced — behaviour is byte-identical to a build
// without the feature. The validator is applied in every code path that sets
// a password: self-service signup, POST /me/password, and POST
// /auth/reset-password. All validation failures return the same generic
// error to prevent enumeration of policy internals.
//
// Password HISTORY (PasswordPolicyConfig.MaxHistory) is a separate mechanism
// — see WithPasswordHistoryStore below — since checking reuse needs a
// per-user store keyed by userID, not just the candidate string
// ValidatePassword receives.
func WithPasswordPolicy(v spi.PasswordPolicyValidator) Option {
	return func(srv *Server) { srv.passwordPolicyValidator = v }
}

// PasswordHistoryStore returns the wired password-history store, or nil if
// history is not enforced (WithPasswordHistoryStore).
func (s *Server) PasswordHistoryStore() core.PasswordHistoryStore {
	return s.passwordHistoryStore
}

// WithPasswordHistoryStore wires a store that remembers a user's recent
// passwords so PasswordPolicyConfig.MaxHistory > 0 can reject reuse. Applied
// at both self-service paths that already run PasswordPolicyValidator: POST
// /me/password and POST /auth/reset-password. NOT applied at signup (a brand
// new account has no prior password to check against) or at admin-initiated
// password resets (interfaces/admin, internal/adminuser — a separate,
// non-SPI validation path).
//
// Nil (the default) means no history is enforced — byte-identical to a build
// without this feature. A CheckHistory error fails OPEN (logged, the change
// proceeds): a history-store outage must never lock a user out of changing
// their own password. A Record error after a successful change is likewise
// logged and non-fatal — the change already succeeded.
func WithPasswordHistoryStore(store core.PasswordHistoryStore) Option {
	return func(s *Server) { s.passwordHistoryStore = store }
}

// passwordMaxAgeDays returns the operator-configured
// PasswordPolicyConfig.MaxAgeDays (via WithPasswordPolicy), or 0 when no
// policy validator is wired, or the wired one doesn't expose it
// (spi.PasswordMaxAgeProvider is an OPTIONAL extension — see
// shared/spi/reg_gate.go). 0 is universally "not enforced" for this
// dimension, matching every other zero-value-means-off policy knob on this
// server (e.g. maxSessionsPerUser).
func (s *Server) passwordMaxAgeDays() int {
	if p, ok := s.passwordPolicyValidator.(spi.PasswordMaxAgeProvider); ok {
		return p.PasswordMaxAgeDays()
	}
	return 0
}

// handleForgotPassword delegates to selfservice.HandleForgotPassword.
func (s *Server) handleForgotPassword(ctx HandlerContext) {
	selfservice.HandleForgotPassword(s, ctx)
}

// handleResetPassword delegates to selfservice.HandleResetPassword.
func (s *Server) handleResetPassword(ctx HandlerContext) {
	selfservice.HandleResetPassword(s, ctx)
}

// handleMyDataExport delegates to selfservice.HandleMyDataExport.
func (s *Server) handleMyDataExport(ctx HandlerContext) {
	selfservice.HandleMyDataExport(s, ctx)
}

// handleMyAccountErase delegates to selfservice.HandleMyAccountErase.
func (s *Server) handleMyAccountErase(ctx HandlerContext) {
	selfservice.HandleMyAccountErase(s, ctx)
}
