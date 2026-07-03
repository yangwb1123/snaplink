package sso

import (
	"context"
	"strings"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/configaudit"
)

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

// applyConfigAuditWiring wires the config-audit change-capture hook (AGENTS.md
// "narrowest existing seam") post-options, in NewServer. Only when BOTH an
// auditor and a configaudit.Store are present, so a build without
// WithConfigAuditStore pays zero cost (the hook is never set, and
// Recorder.Record's nil-check short-circuits on every call).
func (s *Server) applyConfigAuditWiring() {
	if s.auditor != nil && s.configAuditStore != nil {
		s.auditor.SetConfigChangeHook(s.recordConfigHistoryFromAudit)
	}
}

// mountConfigAuditAPI registers the runtime-configuration-audit admin API
// (GET .../config/{running,applied,diff,history}). The snapshot endpoints
// mount only when a config-snapshot source is wired (WithConfigSnapshots);
// history additionally requires WithConfigAuditStore, so a deployment using
// only the change-capture hook (no snapshot wiring) still gets a history
// endpoint without the snapshot/diff routes erroring on every request.
func (s *Server) mountConfigAuditAPI(api Router) {
	if s.configAppliedSnapshot != nil || s.configRunningSnapshotFn != nil {
		api.GET(PathAdminConfigRunning, s.handleConfigRunning)
		api.GET(PathAdminConfigApplied, s.handleConfigApplied)
		api.GET(PathAdminConfigDiff, s.handleConfigDiff)
	}
	if s.configAuditStore != nil {
		api.GET(PathAdminConfigHistory, s.handleConfigHistory)
	}
}

func (s *Server) handleConfigRunning(ctx HandlerContext) { configaudit.HandleRunning(s, ctx) }
func (s *Server) handleConfigApplied(ctx HandlerContext) { configaudit.HandleApplied(s, ctx) }
func (s *Server) handleConfigDiff(ctx HandlerContext)    { configaudit.HandleDiff(s, ctx) }
func (s *Server) handleConfigHistory(ctx HandlerContext) { configaudit.HandleHistory(s, ctx) }

// configHistoryResourceByEventType classifies an audit.EventType into the
// config_history "resource" column, restricted to the event types that
// ALREADY broadcast a cluster Kind*Change (client/tenant/policy) per
// AGENTS.md's change-capture requirement. Every other admin event type is
// skipped: a resource-scoped config_history pairs with the running/applied
// diff endpoint, it is not a second general admin audit log (that already
// exists at /api/v1/audit/events).
var configHistoryResourceByEventType = map[audit.EventType]string{
	audit.EventAdminClientCreated:       "client",
	audit.EventAdminClientUpdated:       "client",
	audit.EventAdminClientDeleted:       "client",
	audit.EventAdminClientSecretRotated: "client",
	audit.EventAdminTenantCreated:       "tenant",
	audit.EventAdminTenantUpdated:       "tenant",
	audit.EventAdminTenantDeleted:       "tenant",
	audit.EventAdminTenantStatusChanged: "tenant",
	audit.EventAdminRoleAdded:           "policy",
	audit.EventAdminRoleUpdated:         "policy",
	audit.EventAdminRoleRemoved:         "policy",
	audit.EventAdminRoleAssigned:        "policy",
	audit.EventAdminRoleUnassigned:      "policy",
	audit.EventAdminMenusUpdated:        "policy",
}

// recordConfigHistoryFromAudit is the audit.Recorder ConfigChangeHook wired
// in NewServer when both an auditor and a configAuditStore are present
// (see sso.go). It is the "narrowest existing seam" AGENTS.md's
// change-capture requirement asks for: every admin mutation across gRPC
// (grpcadmin's recordAdmin helper) and REST already funnels through
// Recorder.Record with the actor stamped from the admin auth context
// (sso.AdminActorFromContext / the REST admin middleware), so hooking here
// captures every client/tenant/policy change without touching a single
// admin_*.go call site.
//
// Limitation (documented, not fixed here — see AGENTS.md scope discipline):
// this generic seam only carries the changed entity's ID (via the
// "target="+id Reason convention every admin handler already uses), not its
// before/after field values, so the recorded Patch is empty — a presence-
// only history entry, not a field-level diff. [Server.RecordConfigChange]
// is the field-accurate alternative for a call site that has both states.
func (s *Server) recordConfigHistoryFromAudit(ctx context.Context, e *audit.Event) {
	resource, ok := configHistoryResourceByEventType[e.Type]
	if !ok || s.configAuditStore == nil {
		return
	}
	entry := configaudit.Entry{
		Actor:      e.ActorID,
		Resource:   resource,
		ResourceID: strings.TrimPrefix(e.Reason, "target="),
		Patch:      []configaudit.Op{},
		Reason:     string(e.Type),
	}
	if err := s.configAuditStore.Record(ctx, entry); err != nil {
		s.logger.Error("config history record failed", "resource", resource, "error", err)
	}
}

// RecordConfigChange appends a field-level config_history entry for a
// single resource mutation: before/after are the resource's own JSON-
// shaped representation (NOT the whole server config) — e.g. a client
// struct round-tripped through json.Marshal/Unmarshal into map[string]any.
// actor should come from the caller's admin auth context
// (sso.AdminActorFromContext for gRPC, the REST admin middleware's stashed
// subject for HTTP). No-op when no configAuditStore is wired, so callers
// may invoke it unconditionally.
func (s *Server) RecordConfigChange(ctx context.Context, actor, tenantID, resource, resourceID string, before, after map[string]any, reason string) {
	if s.configAuditStore == nil {
		return
	}
	entry := configaudit.Entry{
		Actor:      actor,
		TenantID:   tenantID,
		Resource:   resource,
		ResourceID: resourceID,
		Patch:      configaudit.RedactOps(configaudit.Diff(before, after)),
		Reason:     reason,
	}
	if err := s.configAuditStore.Record(ctx, entry); err != nil {
		s.logger.Error("config history record failed", "resource", resource, "resource_id", resourceID, "error", err)
	}
}
