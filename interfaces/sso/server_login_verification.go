package sso

import (
	"net/http"

	"github.com/snaplink/sso/internal/auth/login"
)

// rejectUnverifiedEmail returns true when mandatory email verification is
// enabled AND the authenticated user's email is not yet verified. The check
// occurs AFTER credential verification (oracle-safe: an attacker who knows
// the password cannot distinguish "user doesn't exist" from "unverified").
func (s *Server) rejectUnverifiedEmail(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	if !s.signupRequireVerification {
		return false
	}
	if s.userProvider == nil {
		return false
	}
	u, uerr := s.userProvider.GetByID(ctx.Request().Context(), result.UserID)
	// Fail closed: a store error or missing record cannot confirm verified status.
	if uerr != nil || u == nil || u.Attributes["email_verified"] != "true" {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrEmailNotVerified)
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, ErrEmailNotVerified, req.State))
		return true
	}
	return false
}
