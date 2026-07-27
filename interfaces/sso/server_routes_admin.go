package sso

import (
	"github.com/yangwb1123/snaplink/shared/core"
)

// Token Portfolio admin route-path re-exports (relocated from aliases.go to
// keep that file within the per-file line budget). Consumed by the admin
// token-portfolio route mounts below.
const (
	PathAdminTokenPortfolio  = core.PathAdminTokenPortfolio
	PathAdminTokenSubject    = core.PathAdminTokenSubject
	PathAdminTokenExpiring   = core.PathAdminTokenExpiring
	PathAdminTokenSuspicious = core.PathAdminTokenSuspicious
	PathAdminTokenBulkRevoke = core.PathAdminTokenBulkRevoke
	// PathCheckSessionIframe re-exports core.PathCheckSessionIframe (OpenID
	// Connect Session Management 1.0 §2) here — rather than in aliases.go,
	// which sits at the file-line budget — for the endpoint-inventory entry
	// below; interfaces/sso/server_userinfo.go and server_discovery_config.go
	// reference this SAME package-level const.
	PathCheckSessionIframe = core.PathCheckSessionIframe
)

// Crypto-material-inventory admin route-path re-exports moved to aliases.go
// (which now has room; this file was at its line budget adding the
// wasmauthz mount call below).

// Admin REST API route registration, extracted from Mount (server_routes.go).
// All routes hang off the /api/v1 group created in Mount; the /api/v1/admin/*
// paths are gated by AdminMiddleware (GET admin:read, mutations admin:write).
// Each block is gated on its backing store so the registered route set is
// byte-identical to the previous inline assembly.

// mountAdminSurface registers the entire /api/v1/admin/* REST surface (plus
// the un-prefixed /api/v1/clients/:id lookup that shares its group). The
// group is ALWAYS created — unlike every other FeatureGates-gated surface,
// AdminAPI is hot-reloadable (config/reload's SetAdminAPIGateHook ->
// Server.SetAdminAPIGateEnabled), so Mount() can no longer decide "gate off
// ⇒ don't register" once, at boot: the group is wrapped in a
// core.GatedRouter keyed on adminAPIGateOn (itself backed by the LIVE
// adminAPILive flag, sso_wiring.go) instead. Gate off ⇒ every route in the
// group answers http.NotFound — byte-identical to the router-native 404 a
// truly-unregistered path gets, still indistinguishable from a path that
// was never defined to an outside probe, but now flippable without a
// restart. See GatedRouter's doc (shared/core/router.go) for why this has
// to wrap the HANDLER rather than ride along as a Group middleware.
func (s *Server) mountAdminSurface() {
	api := core.NewGatedRouter(s.router.Group(PathAPIPrefix), s.adminAPIGateOn)
	s.mountAdminAPIObservability(api)
	s.mountAdminUserState(api)
	s.mountAdminB2B(api)
	s.mountConfigAuditAPI(api)
	s.mountAdminBreakGlass(api)
	s.mountCryptoInventoryAPI(api)
	s.mountWebhookAdminAPI(api)
	s.mountRebacAdminAPI(api)
	s.mountWASMAuthzAdminAPI(api)
	s.mountAdminCompliance(api)
	s.mountAdminChangeApproval(api)
	s.mountAPIDocsUI(api)
}

// mountAdminAPIObservability registers the client lookup plus the opt-in audit,
// network-policy, per-tenant usage/metering read APIs, and the runtime
// endpoint inventory.
func (s *Server) mountAdminAPIObservability(api Router) {
	api.GET(PathClientByID, s.handleGetClient)
	api.GET(PathAdminEndpoints, s.handleAdminEndpoints)
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
	// Tenant branding CRUD (opt-in: requires tenant store).
	if s.tenantStore != nil {
		api.GET(PathAdminBranding, s.handleAdminGetBranding)
		api.PUT(PathAdminBranding, s.handleAdminUpdateBranding)
		api.DELETE(PathAdminBranding, s.handleAdminDeleteBranding)
	}
	s.mountAdminTokenGovernance(api)
	s.mountAdminAPILifecycle(api)
}

// mountAdminTokenGovernance registers the token-governance read/action surface:
// the usage telemetry read API, the Phase-3 Token Portfolio suite (overview +
// per-subject view + expiry calendar + bulk-revoke), the token-policy
// governance view, and the suspicious-token anomaly list. Each block is gated
// on its own opt-in backing so the registered route set is byte-identical to
// a build without the feature.
func (s *Server) mountAdminTokenGovernance(api Router) {
	// Token-usage telemetry + the Token Portfolio panel APIs (opt-in
	// WithTokenUsageRecorder). The whole panel surface — overview, per-subject
	// active-token view, expiry calendar, and the bulk-revoke workflow — is
	// gated on the usage recorder that backs the panel; the subject/expiring/
	// revoke handlers degrade gracefully when no refresh store is wired (or
	// the wired store doesn't implement the optional extension). Admin-gated
	// (GET admin:read, POST admin:write) via the /api/v1/admin/ prefix.
	if s.tokenUsageRecorder != nil {
		api.GET(PathAdminTokenUsage, s.handleAdminTokenUsage)
		api.GET(PathAdminTokenPortfolio, s.handleAdminTokenPortfolio)
		api.GET(PathAdminTokenSubject, s.handleAdminTokenSubject)
		api.GET(PathAdminTokenExpiring, s.handleAdminTokenExpiring)
		api.POST(PathAdminTokenBulkRevoke, s.handleAdminBulkRevoke)
	}
	// Token-policy governance read API (opt-in WithTokenPolicy). Admin-gated
	// (admin:read); not mounted without a store — byte-identical without it.
	if s.tokenPolicyStore != nil {
		api.GET(PathAdminTokenPolicies, s.handleAdminTokenPolicies)
	}
	// Suspicious-token anomaly list (opt-in WithTokenAnomalyDetector). Read-only
	// governance/reporting; not mounted without a detector — byte-identical
	// without it.
	if s.tokenAnomalyDetector != nil {
		api.GET(PathAdminTokenSuspicious, s.handleAdminTokenSuspicious)
	}

	// Threat-policy CRUD (Active ITDR, opt-in WithThreatPolicyStore).
	// Admin-gated (GET admin:read, PUT/DELETE admin:write) via the
	// /api/v1/admin/ prefix. Not mounted without a store — byte-identical
	// to a build without the feature.
	if s.threatPolicyStore != nil {
		api.GET(PathAdminThreatPolicies, s.handleAdminListThreatPolicies)
		api.GET(PathAdminThreatPolicyByID, s.handleAdminGetThreatPolicy)
		api.PUT(PathAdminThreatPolicyByID, s.handleAdminPutThreatPolicy)
		api.DELETE(PathAdminThreatPolicyByID, s.handleAdminDeleteThreatPolicy)
	}
}

// mountAdminAPILifecycle registers the admin management/lifecycle endpoints
// (backup, admin-token lifecycle, session listing, credential inventory).
// Split from mountAdminAPIObservability purely to keep each under the
// function-length budget; every block is opt-in and byte-identical when its
// backing store/registry is unwired.
func (s *Server) mountAdminAPILifecycle(api Router) {
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
	// Cross-protocol session-hub query: every session/protocol for one
	// subject, grouped by global_sid. s.sessionHub is always non-nil
	// (constructed unconditionally in NewServer), so always mounted.
	api.GET(PathAdminSessionsLinked, s.handleAdminLinkedSessions)
	// Credential-rotation governance inventory (opt-in WithCredentialRotation).
	// Not mounted without a registry — byte-identical to a build without it.
	if s.credentialRegistry != nil {
		api.GET(PathAdminCredentials, s.handleAdminListCredentials)
	}
	s.mountAdminAPILifecycleExtra(api)
}

// mountAdminAPILifecycleExtra registers the rest of the lifecycle surface —
// credential compromise-response, the event stream, CAP, and DR mode — split
// out of mountAdminAPILifecycle to stay under the function-length budget.
func (s *Server) mountAdminAPILifecycleExtra(api Router) {
	// Emergency credential compromise-response (opt-in WithCredentialCompromise).
	// admin:write via the default AdminMiddleware method-scope rule.
	if s.credentialScheduler != nil {
		api.POST(PathAdminCredentialCompromise, s.handleAdminCompromiseCredential)
	}
	// Realtime admin event stream (opt-in WithSSEBroker). Mounted only when
	// a broker is wired — byte-identical to a build without it.
	if s.sseBroker != nil {
		api.GET(PathAdminEventsStream, s.handleAdminEventsStream)
	}
	// Zero-trust conditional-access governance view (opt-in
	// WithConditionalAccess). Read-only; not mounted without the engine —
	// byte-identical to a build without it.
	if s.capStore != nil {
		api.GET(PathAdminAccessPolicies, s.handleAdminListAccessPolicies)
	}
	// DR degraded-service mode read + toggle (opt-in WithDegradationManager).
	// Admin-gated (GET admin:read, POST admin:write) via the /api/v1/admin/
	// prefix. Not mounted without the manager — byte-identical to a build
	// without the feature.
	if s.degradation != nil {
		api.GET(PathDRMode, s.handleGetDRMode)
		api.POST(PathDRMode, s.handleSetDRMode)
	}
}

// mountAdminUserState registers admin user-state management. Reuses /me stores.
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
		// Local user entity CRUD — see mountAdminLocalUserCRUD's doc
		// (signing_key_aggregation.go — relocated there purely for the
		// free space, no thematic relationship) for why it's a separate
		// function and a separate path from the gateway's /admin/users.
		s.mountAdminLocalUserCRUD(api)
	}
	if s.deviceSecretStore != nil {
		api.DELETE(PathAdminUserDeviceSecrets, s.handleAdminRevokeUserDeviceSecrets)
	}
	if s.refreshTokenStore != nil {
		api.DELETE(PathAdminUserRefreshTokens, s.handleAdminRevokeUserRefreshTokens)
	}
	if s.passwordResetStore != nil {
		api.GET(PathAdminUserPasswordResetTokens, s.handleAdminListUserPasswordResetTokens)
		api.DELETE(PathAdminUserPasswordResetTokens, s.handleAdminRevokeUserPasswordResetTokens)
	}
	s.mountAdminDeviceUserRoutes(api)
	if s.emailChangeStore != nil {
		api.GET(PathAdminUserEmailChangeTokens, s.handleAdminListUserEmailChangeTokens)
		api.DELETE(PathAdminUserEmailChangeTokens, s.handleAdminRevokeUserEmailChangeTokens)
	}
	if s.accountLockout != nil {
		api.POST(PathAdminAccountLockoutClear, s.handleAdminClearAccountLockout)
	}
	if s.userLifecycleStore != nil && s.userProvider != nil {
		api.GET(PathAdminUserLifecycle, s.handleAdminGetUserLifecycle)
		api.POST(PathAdminUserLifecycle, s.handleAdminTransitionUserLifecycle)
	}
	if s.recoveryCodeStore != nil { api.POST(PathAdminUserRecoveryCodes, s.handleAdminResetUserRecoveryCodes) }
	if s.loginHistory != nil { api.GET(PathAdminUserLoginHistory, s.handleAdminListUserLoginHistory) }
}

// mountAdminDeviceUserRoutes registers the device-related admin routes.
func (s *Server) mountAdminDeviceUserRoutes(api Router) {
	if s.deviceStore == nil { return }
	api.GET(PathAdminUserDevices, s.handleAdminListUserDevices)
	api.DELETE(PathAdminUserDeviceByID, s.handleAdminDeleteUserDevice)
	api.GET(PathAdminDevices, s.handleAdminListAllDevices)
	api.GET(PathAdminDeviceStats, s.handleAdminDeviceStats)
	api.POST(PathAdminDevicesBulkRevoke, s.handleAdminBulkRevokeDevices)
	api.GET(PathAdminDeviceActivity, s.handleAdminDeviceActivity)
	api.POST(PathAdminDeviceTrustReset, s.handleAdminResetDeviceTrust)
	api.GET(PathAdminSecurityActivity, s.handleAdminListSecurityActivity)
}

// mountAdminB2B registers the admin management of enterprise connections,
// tenant membership, and invitations. Mounted only when the backing store is
// wired — byte-identical without them.
func (s *Server) mountAdminB2B(api Router) {
	if s.providerStore != nil {
		api.GET(PathAdminProviders, s.handleAdminListProviders)
		api.POST(PathAdminProviders, s.handleAdminCreateProvider)
		api.GET(PathAdminProviderByID, s.handleAdminGetProvider)
		api.PUT(PathAdminProviderByID, s.handleAdminUpdateProvider)
		api.DELETE(PathAdminProviderByID, s.handleAdminDeleteProvider)
	}
	if s.connectionStore != nil {
		api.GET(PathAdminConnections, s.handleAdminListConnections)
		api.POST(PathAdminConnections, s.handleAdminUpsertConnection)
		api.GET(PathAdminConnectionByID, s.handleAdminGetConnection)
		api.DELETE(PathAdminConnectionByID, s.handleAdminDeleteConnection)
		api.GET(PathAdminConnectionDomains, s.handleAdminListConnectionDomains)
		api.POST(PathAdminConnectionDomainVerify, s.handleAdminVerifyConnectionDomain)
		api.GET(PathAdminConnectionHealth, s.handleAdminGetConnectionHealth)
		api.POST(PathAdminConnectionProbe, s.handleAdminProbeConnection)
	}
	if s.tenantUserStore != nil {
		api.GET(PathAdminTenantMembers, s.handleAdminListTenantMembers)
		api.PUT(PathAdminTenantMemberByID, s.handleAdminPutTenantMember)
		api.DELETE(PathAdminTenantMemberByID, s.handleAdminRemoveTenantMember)
		// Tenant export needs the roster (TenantUserStore) as its anchor
		// dependency for the members/users sections; every other section
		// (clients/connections/permissions/sessions/audit) is independently
		// nil-gated inside compliance.TenantExporter, so this mount point is
		// the natural "tenant management is wired at all" gate.
		api.POST(PathAdminTenantExport, s.handleAdminExportTenant)
	}
	if s.invitationStore != nil {
		api.POST(PathAdminTenantInvitations, s.handleAdminSendInvitation)
		api.GET(PathAdminTenantInvitations, s.handleAdminListInvitations)
		api.DELETE(PathAdminTenantInvitationByEmail, s.handleAdminRevokeInvitation)
	}
}

// applyConfigAuditWiring, mountConfigAuditAPI, and the handleConfig* wrappers
// live in server_invalidation.go (relocated there — it already imports
// configaudit for the drift-digest helpers — to hold this file under the
// 500-line maintainability budget).

// mountAdminBreakGlass moved to server_admin_handlers.go (beside the
// break-glass handlers it wires; this file was at its line budget adding the
// token-expiry-calendar route below).

// mountCryptoInventoryAPI moved to signing_key_aggregation.go (admin-facing
// crypto-material surface; this file was at the line budget).

// mountOrgAdminSelfService moved to sso_selfservice.go (a better thematic
// home, and this file was at the line budget).
