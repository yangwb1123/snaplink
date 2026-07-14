package sso

import (
	"context"
	"net/http"
	"time"

	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/protocols/selfservice"
	"github.com/snaplink/sso/protocols/selfservice/selfservicecore"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

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
