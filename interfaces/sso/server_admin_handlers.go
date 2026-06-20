package sso

import (
	"github.com/snaplink/sso/interfaces/admin"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/selfservice"
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

// recordAdminUserAction emits an admin_* audit event for a helpdesk action on a
// user's state. ActorID is the acting ADMIN (from the AdminMiddleware-stamped
// context). Retained in root for the B2B org handlers (admin/users.go has its
// own copy for the extracted user-management handlers).
func (s *Server) recordAdminUserAction(ctx HandlerContext, evtType audit.EventType, targetUser, metaKey, metaVal string) {
	if s.auditor == nil {
		return
	}
	actor, _, _ := AdminActorFromContext(ctx.Request().Context())
	evt := &audit.Event{
		Type:    evtType,
		Outcome: audit.OutcomeSuccess,
		ActorID: actor,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "target_user", targetUser)
	if metaKey != "" {
		audit.SetMeta(evt, metaKey, metaVal)
	}
	s.auditor.Record(ctx.Request().Context(), evt)
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
