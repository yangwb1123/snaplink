package sso

// Admin REST API route registration, extracted from Mount (server_routes.go).
// All routes hang off the /api/v1 group created in Mount; the /api/v1/admin/*
// paths are gated by AdminMiddleware (GET admin:read, mutations admin:write).
// Each block is gated on its backing store so the registered route set is
// byte-identical to the previous inline assembly.

// mountAdminAPIObservability registers the client lookup plus the opt-in audit,
// network-policy, and per-tenant usage/metering read APIs.
func (s *Server) mountAdminAPIObservability(api Router) {
	api.GET(PathClientByID, s.handleGetClient)
	if s.auditAPI && s.auditor != nil {
		api.GET(PathAuditEvents, s.handleAuditEvents)
		api.GET(PathAuditEventByID, s.handleAuditEventByID)
		api.GET(PathAuditFacets, s.handleAuditFacets)
	}
	if s.netAPI && s.netStore != nil {
		api.GET(PathNetPolicies, s.handleListNetPolicies)
		api.GET(PathNetPolicyByName, s.handleGetNetPolicy)
		api.POST(PathNetPolicies, s.handleApplyNetPolicy)
		api.DELETE(PathNetPolicyByName, s.handleDeleteNetPolicy)
		api.GET(PathNetPolicyClassify, s.handleClassifyNetPolicy)
		api.GET(PathNetPolicyResolveMe, s.handleResolveMeNetPolicy)
	}

	// Per-tenant usage/metering endpoint (opt-in WithTenantUsageAggregator).
	// Gated by AdminMiddleware (admin:read) via the /api/v1/admin/ prefix.
	// Not mounted without the aggregator — byte-identical to a build without it.
	if s.usageAggregator != nil {
		api.GET(PathTenantUsage, s.handleTenantUsage)
		api.GET(PathAdminTopTenants, s.handleAdminTopTenants)
	}
	// SQLite backup trigger (opt-in WithBackupSource). Requires at least one
	// registered backup source; byte-identical when none are wired.
	if len(s.backupSources) > 0 {
		api.POST(PathBackup, s.handleAdminBackup)
	}
	// Admin token lifecycle (opt-in WithAdminTokenStore). Without the
	// store, admin tokens have no management surface.
	if s.adminTokenStore != nil {
		api.GET(PathAdminTokens, s.handleAdminListTokens)
		api.POST(PathAdminLogout, s.handleAdminLogout)
		api.DELETE(PathAdminTokenByID, s.handleAdminRevokeToken)
	}
	// Admin session listing (opt-in WithSessionManager). Without a session
	// manager the admin SPA's sessions panel shows nothing.
	if s.sessionMgr != nil {
		api.GET(PathAdminSessions, s.handleAdminListSessions)
	}
}

// mountAdminUserState registers the admin/helpdesk management of a user's
// self-service state. Each block reuses the SAME store the user's own /me
// endpoints use, so an admin and the user see one consistent view. Mounted only
// when the backing store is wired — byte-identical without them.
func (s *Server) mountAdminUserState(api Router) {
	if s.consentStore != nil {
		api.GET(PathAdminUserConsents, s.handleAdminListUserConsents)
		api.DELETE(PathAdminUserConsentByID, s.handleAdminRevokeUserConsent)
	}
	if s.mfaEnrollmentStore != nil {
		api.GET(PathAdminUserMFA, s.handleAdminListUserMFA)
		api.DELETE(PathAdminUserMFAByID, s.handleAdminRemoveUserMFA)
	}
	if s.passwordCredentialStore != nil {
		api.POST(PathAdminUserPassword, s.handleAdminResetUserPassword)
	}
	if s.userProvider != nil {
		api.POST(PathAdminUserEmail, s.handleAdminSetUserEmail)
	}
	if s.deviceSecretStore != nil {
		api.DELETE(PathAdminUserDeviceSecrets, s.handleAdminRevokeUserDeviceSecrets)
	}
	if s.passwordResetStore != nil {
		api.GET(PathAdminUserPasswordResetTokens, s.handleAdminListUserPasswordResetTokens)
		api.DELETE(PathAdminUserPasswordResetTokens, s.handleAdminRevokeUserPasswordResetTokens)
	}
	if s.emailChangeStore != nil {
		api.GET(PathAdminUserEmailChangeTokens, s.handleAdminListUserEmailChangeTokens)
		api.DELETE(PathAdminUserEmailChangeTokens, s.handleAdminRevokeUserEmailChangeTokens)
	}
	if s.accountLockout != nil {
		api.POST(PathAdminAccountLockoutClear, s.handleAdminClearAccountLockout)
	}
}

// mountAdminB2B registers the admin management of enterprise connections,
// tenant membership, and invitations. Mounted only when the backing store is
// wired — byte-identical without them.
func (s *Server) mountAdminB2B(api Router) {
	if s.connectionStore != nil {
		api.GET(PathAdminConnections, s.handleAdminListConnections)
		api.POST(PathAdminConnections, s.handleAdminUpsertConnection)
		api.GET(PathAdminConnectionByID, s.handleAdminGetConnection)
		api.DELETE(PathAdminConnectionByID, s.handleAdminDeleteConnection)
	}
	if s.tenantUserStore != nil {
		api.GET(PathAdminTenantMembers, s.handleAdminListTenantMembers)
		api.PUT(PathAdminTenantMemberByID, s.handleAdminPutTenantMember)
		api.DELETE(PathAdminTenantMemberByID, s.handleAdminRemoveTenantMember)
	}
	if s.invitationStore != nil {
		api.POST(PathAdminTenantInvitations, s.handleAdminSendInvitation)
		api.GET(PathAdminTenantInvitations, s.handleAdminListInvitations)
		api.DELETE(PathAdminTenantInvitationByEmail, s.handleAdminRevokeInvitation)
	}
}

// mountAdminBreakGlass registers the break-glass (emergency support) admin
// session lifecycle: create (bounded, audited on-behalf-of grant, reason
// mandatory), list pending+active, revoke (cascades derived-session
// destruction), approve (two-person rule — the approver must differ from the
// creator). Mounted only when a BreakGlassStore is wired — byte-identical
// without it. GET is admin:read; POST/DELETE are admin:write via the
// default AdminMiddleware method-scope rule.
func (s *Server) mountAdminBreakGlass(api Router) {
	if s.breakGlassStore == nil {
		return
	}
	api.POST(PathAdminBreakGlass, s.handleAdminCreateBreakGlass)
	api.GET(PathAdminBreakGlass, s.handleAdminListBreakGlass)
	api.DELETE(PathAdminBreakGlassByID, s.handleAdminRevokeBreakGlass)
	api.POST(PathAdminBreakGlassApprove, s.handleAdminApproveBreakGlass)
}
