package sso

import (
	"github.com/snaplink/sso/selfservice"
)

// handleForgotPassword delegates to selfservice.HandleForgotPassword.
func (s *Server) handleForgotPassword(ctx HandlerContext) {
	selfservice.HandleForgotPassword(s, ctx)
}

// handleResetPassword delegates to selfservice.HandleResetPassword.
func (s *Server) handleResetPassword(ctx HandlerContext) {
	selfservice.HandleResetPassword(s, ctx)
}
