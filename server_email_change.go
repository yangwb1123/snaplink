package sso

import (
	"github.com/snaplink/sso/selfservice"
	"github.com/snaplink/sso/spi"
)

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
