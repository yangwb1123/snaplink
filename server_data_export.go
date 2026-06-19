package sso

import (
	"github.com/snaplink/sso/selfservice"
)

// handleMyDataExport delegates to selfservice.HandleMyDataExport.
func (s *Server) handleMyDataExport(ctx HandlerContext) {
	selfservice.HandleMyDataExport(s, ctx)
}

// handleMyAccountErase delegates to selfservice.HandleMyAccountErase.
func (s *Server) handleMyAccountErase(ctx HandlerContext) {
	selfservice.HandleMyAccountErase(s, ctx)
}
