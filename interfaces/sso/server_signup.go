package sso

import (
	"context"
	"time"

	"github.com/snaplink/sso/protocols/selfservice"
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

// ErrorBody creates an error response body.
func (s *Server) ErrorBody(errCode string) map[string]any {
	result := make(map[string]any)
	for k, v := range errorBody(errCode) {
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

// EmailVerificationTTL returns the email verification token TTL.
func (s *Server) EmailVerificationTTL() time.Duration {
	return s.emailVerificationTTL
}

// PasswordPolicyValidator returns the wired password policy validator, or nil
// if no policy is enforced.
func (s *Server) PasswordPolicyValidator() spi.PasswordPolicyValidator {
	return s.passwordPolicyValidator
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
