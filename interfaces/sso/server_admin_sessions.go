package sso

import "net/http"

// handleAdminListSessions returns all active sessions (delegates to
// SessionManager.ListAll). Gated by admin:read scope via the admin
// middleware. Mounted only when a SessionManager is wired.
func (s *Server) handleAdminListSessions(ctx HandlerContext) {
	if s.sessionMgr == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrNotFound))
		return
	}
	sessions, err := s.sessionMgr.ListAll(ctx.Request().Context())
	if err != nil {
		s.logger.Error("admin list sessions failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	if sessions == nil {
		sessions = []*Session{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus: StatusOK,
		"sessions": sessions,
		"total":   len(sessions),
	})
}
