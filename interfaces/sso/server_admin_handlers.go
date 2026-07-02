package sso

import (
	"github.com/snaplink/sso/interfaces/admin"
	"github.com/snaplink/sso/protocols/selfservice"
	"github.com/snaplink/sso/shared/core"
	"net/http"
)

// Admin/helpdesk user-management handlers are thin wrappers delegating to the
// admin package's HandleAdminX free functions (*Server satisfies admin.Deps via
// accessor methods); the logic + audit live in admin/users.go. recordAdminUserAction
// stays here because the B2B org handlers (server_b2b_handlers.go) still use it.

func (s *Server) handleAdminListUserConsents(ctx HandlerContext) {
	admin.HandleAdminListUserConsents(s, ctx)
}
func (s *Server) handleAdminRevokeUserConsent(ctx HandlerContext) {
	admin.HandleAdminRevokeUserConsent(s, ctx)
}
func (s *Server) handleAdminListUserMFA(ctx HandlerContext) { admin.HandleAdminListUserMFA(s, ctx) }
func (s *Server) handleAdminRemoveUserMFA(ctx HandlerContext) {
	admin.HandleAdminRemoveUserMFA(s, ctx)
}
func (s *Server) handleAdminResetUserPassword(ctx HandlerContext) {
	admin.HandleAdminResetUserPassword(s, ctx)
}
func (s *Server) handleAdminSetUserEmail(ctx HandlerContext) {
	admin.HandleAdminSetUserEmail(s, ctx)
}
func (s *Server) handleAdminClearAccountLockout(ctx HandlerContext) {
	admin.HandleAdminClearAccountLockout(s, ctx)
}
func (s *Server) handleAdminResetUserRecoveryCodes(ctx HandlerContext) {
	admin.HandleAdminResetUserRecoveryCodes(s, ctx)
}
func (s *Server) handleAdminRevokeUserDeviceSecrets(ctx HandlerContext) {
	admin.HandleAdminRevokeUserDeviceSecrets(s, ctx)
}
func (s *Server) handleAdminRevokeUserPasswordResetTokens(ctx HandlerContext) {
	admin.HandleAdminRevokeUserPasswordResetTokens(s, ctx)
}
func (s *Server) handleAdminRevokeUserEmailChangeTokens(ctx HandlerContext) {
	admin.HandleAdminRevokeUserEmailChangeTokens(s, ctx)
}
func (s *Server) handleAdminListUserPasswordResetTokens(ctx HandlerContext) {
	admin.HandleAdminListUserPasswordResetTokens(s, ctx)
}
func (s *Server) handleAdminListUserEmailChangeTokens(ctx HandlerContext) {
	admin.HandleAdminListUserEmailChangeTokens(s, ctx)
}

// B2B org-management handlers — thin wrappers. The enterprise-connection,
// tenant-membership, and invitation admin logic lives in admin/{connections,tenants}.go;
// the self-service /me organization endpoints in selfservice/organizations.go.

// Enterprise connections (admin).
func (s *Server) handleAdminListConnections(ctx HandlerContext) {
	admin.HandleAdminListConnections(s, ctx)
}
func (s *Server) handleAdminGetConnection(ctx HandlerContext) { admin.HandleAdminGetConnection(s, ctx) }
func (s *Server) handleAdminUpsertConnection(ctx HandlerContext) {
	admin.HandleAdminUpsertConnection(s, ctx)
}
func (s *Server) handleAdminDeleteConnection(ctx HandlerContext) {
	admin.HandleAdminDeleteConnection(s, ctx)
}
func (s *Server) handleAdminListConnectionDomains(ctx HandlerContext) {
	admin.HandleAdminListConnectionDomains(s, ctx)
}
func (s *Server) handleAdminVerifyConnectionDomain(ctx HandlerContext) {
	admin.HandleAdminVerifyConnectionDomain(s, ctx)
}

// Tenant membership (admin).
func (s *Server) handleAdminListTenantMembers(ctx HandlerContext) {
	admin.HandleAdminListTenantMembers(s, ctx)
}
func (s *Server) handleAdminPutTenantMember(ctx HandlerContext) {
	admin.HandleAdminPutTenantMember(s, ctx)
}
func (s *Server) handleAdminRemoveTenantMember(ctx HandlerContext) {
	admin.HandleAdminRemoveTenantMember(s, ctx)
}

// Invitations (admin).
func (s *Server) handleAdminSendInvitation(ctx HandlerContext) {
	admin.HandleAdminSendInvitation(s, ctx)
}
func (s *Server) handleAdminListInvitations(ctx HandlerContext) {
	admin.HandleAdminListInvitations(s, ctx)
}
func (s *Server) handleAdminRevokeInvitation(ctx HandlerContext) {
	admin.HandleAdminRevokeInvitation(s, ctx)
}

// Self-service organization endpoints (/me).
func (s *Server) handleMyOrganizations(ctx HandlerContext) {
	selfservice.HandleMyOrganizations(s, ctx)
}
func (s *Server) handleLeaveMyOrganization(ctx HandlerContext) {
	selfservice.HandleLeaveMyOrganization(s, ctx)
}
func (s *Server) handleAcceptInvitation(ctx HandlerContext) {
	selfservice.HandleAcceptInvitation(s, ctx)
}

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
		KeyStatus:  StatusOK,
		"sessions": sessions,
		"total":    len(sessions),
	})
}

// handleAdminListTokens returns the active admin bearer tokens.
func (s *Server) handleAdminListTokens(ctx HandlerContext) {
	if s.adminTokenStore == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrNotFound))
		return
	}
	// Optional query param ?admin_id= to filter by issuing admin.
	adminID := ctx.Query("admin_id")
	tokens, err := s.adminTokenStore.List(ctx.Request().Context(), adminID)
	if err != nil {
		s.logger.Error("admin list tokens failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus: StatusOK,
		"tokens":  tokens,
	})
}

// handleAdminRevokeToken revokes a single admin bearer token by ID.
func (s *Server) handleAdminRevokeToken(ctx HandlerContext) {
	if s.adminTokenStore == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrNotFound))
		return
	}
	tokenID := ctx.Param("id")
	if tokenID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if err := s.adminTokenStore.Revoke(ctx.Request().Context(), tokenID); err != nil {
		s.logger.Error("admin revoke token failed", "id", tokenID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusOK})
}

// handleAdminLogout revokes the admin bearer token used in the current
// request. The token is validated and its jti (matching AdminToken.ID)
// is used to revoke it. On success the caller should discard the token.
func (s *Server) handleAdminLogout(ctx HandlerContext) {
	if s.adminTokenStore == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrNotFound))
		return
	}
	token := bearerToken(ctx.Request())
	if token == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(core.ErrUnauthorized))
		return
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), token)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(core.ErrInvalidToken))
		return
	}
	if claims.JTI == "" {
		s.logger.Error("admin logout: token has no jti")
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if err := s.adminTokenStore.Revoke(ctx.Request().Context(), claims.JTI); err != nil {
		s.logger.Error("admin logout revoke failed", "jti", claims.JTI, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: "logged_out"})
}
