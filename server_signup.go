package sso

import (
	"context"
	"time"

	"github.com/snaplink/sso/selfservice"
	"github.com/snaplink/sso/spi"
)

// handleSelfRegister delegates to selfservice.HandleSelfRegister.
func (s *Server) handleSelfRegister(ctx HandlerContext) {
	selfservice.HandleSelfRegister(s, ctx)
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
