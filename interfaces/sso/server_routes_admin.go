package sso

import (
	"context"
	"net/http"
	"strings"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/configaudit"
	"github.com/snaplink/sso/protocols/oauth"
)

// Admin REST API route registration, extracted from Mount (server_routes.go).
// All routes hang off the /api/v1 group created in Mount; the /api/v1/admin/*
// paths are gated by AdminMiddleware (GET admin:read, mutations admin:write).
// Each block is gated on its backing store so the registered route set is
// byte-identical to the previous inline assembly.

// mountAdminSurface registers the entire /api/v1/admin/* REST surface (plus
// the un-prefixed /api/v1/clients/:id lookup that shares its group), gated
// on AdminAPI. Off ⇒ Mount() never creates the group at all, so a probe
// against any admin path gets the router's native 404 — indistinguishable
// from a path that was never defined, rather than an admin bearer-auth
// challenge telling a scanner the surface exists.
func (s *Server) mountAdminSurface() {
	if !s.adminAPIGateOn() {
		return
	}
	api := s.router.Group(PathAPIPrefix)
	s.mountAdminAPIObservability(api)
	s.mountAdminUserState(api)
	s.mountAdminB2B(api)
	s.mountConfigAuditAPI(api)
	s.mountAdminBreakGlass(api)
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
	// Token-usage telemetry read API (opt-in WithTokenUsageRecorder). Gated by
	// AdminMiddleware (admin:read) via the /api/v1/admin/ prefix. Not mounted
	// without a recorder — byte-identical to a build without it.
	if s.tokenUsageRecorder != nil {
		api.GET(PathAdminTokenUsage, s.handleAdminTokenUsage)
	}
	// Token-policy governance read API (opt-in WithTokenPolicy). Admin-gated
	// (admin:read); not mounted without a store — byte-identical without it.
	if s.tokenPolicyStore != nil {
		api.GET(PathAdminTokenPolicies, s.handleAdminTokenPolicies)
	}
	s.mountAdminAPILifecycle(api)
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
	// Credential-rotation governance inventory (opt-in WithCredentialRotation).
	// Not mounted without a registry — byte-identical to a build without it.
	if s.credentialRegistry != nil {
		api.GET(PathAdminCredentials, s.handleAdminListCredentials)
	}
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

// endpointInfo is one entry the runtime inventory (GET
// /api/v1/admin/endpoints) reports: the HTTP method, full wire path, and the
// FeatureGates surface (or "core" for an always-on route) it belongs to.
type endpointInfo struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Feature string `json:"feature"`
}

// endpointCandidate pairs an endpointInfo with the predicate deciding
// whether THIS server instance actually registered it. This table is
// presentation-only — Mount() (server_routes.go / server_routes_admin.go /
// server_federation.go) is the single source of truth for what gets wired;
// keep a candidate's `on` in sync with its route's real mount condition
// whenever that condition changes, or the inventory drifts from reality.
type endpointCandidate struct {
	endpointInfo
	on func(s *Server) bool
}

func alwaysOn(*Server) bool { return true }

// coreEndpointCandidates lists the routes mounted unconditionally by
// mountCoreOAuthOIDC — every deployment shape exposes these regardless of
// FeatureGates.
func coreEndpointCandidates() []endpointCandidate {
	core := []struct {
		method, path string
	}{
		{http.MethodGet, PathHealth},
		{http.MethodGet, PathStatus},
		{http.MethodGet, PathJWKS},
		{http.MethodGet, PathOIDCDiscovery},
		{http.MethodGet, PathOAuthAuthorizationServerMetadata},
		{http.MethodPost, PathLogin},
		{http.MethodPost, PathMFAComplete},
		{http.MethodPost, PathSendCode},
		{http.MethodGet, PathCallback},
		{http.MethodPost, PathToken},
		{http.MethodPost, PathIntrospect},
		{http.MethodPost, PathRevoke},
		{http.MethodPost, PathRevokeAll},
		{http.MethodPost, PathDeviceCode},
		{http.MethodGet, PathDeviceVerify},
		{http.MethodPost, PathDeviceVerify},
		{http.MethodPost, PathPAR},
		{http.MethodPost, oauth.PathRegister},
		{http.MethodGet, oauth.PathRegisterByID},
		{http.MethodPut, oauth.PathRegisterByID},
		{http.MethodDelete, oauth.PathRegisterByID},
		{http.MethodPost, PathLogout},
	}
	out := make([]endpointCandidate, 0, len(core))
	for _, r := range core {
		out = append(out, endpointCandidate{endpointInfo{r.method, r.path, "core"}, alwaysOn})
	}
	return out
}

// gatedProtocolEndpointCandidates lists the routes each of OIDC/CIBA/CAEP/
// Federation directly control — see FeatureGates for what each surface covers.
func gatedProtocolEndpointCandidates() []endpointCandidate {
	return []endpointCandidate{
		{endpointInfo{http.MethodGet, PathUserInfo, "oidc"}, func(s *Server) bool { return s.oidcGateOn() }},
		{endpointInfo{http.MethodGet, PathEndSession, "oidc"}, func(s *Server) bool { return s.oidcGateOn() }},
		{endpointInfo{http.MethodPost, PathBackchannelAuth, "ciba"}, func(s *Server) bool { return s.cibaGateOn() }},
		{endpointInfo{http.MethodPost, PathSSFReceive, "caep"}, func(s *Server) bool {
			return s.caepGateOn() && s.caepReceiver != nil
		}},
		{endpointInfo{http.MethodGet, PathProtectedResourceMetadata, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.protectedResourceMetadata != nil
		}},
		{endpointInfo{http.MethodGet, PathFederationEntityConfig, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.federationEntity != nil
		}},
		{endpointInfo{http.MethodGet, PathFederationFetch, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.federationEntity != nil && s.federationEntity.HasSubordinates()
		}},
		{endpointInfo{http.MethodGet, PathHomeRealm, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.connectionStore != nil
		}},
		{endpointInfo{http.MethodPost, PathHomeRealm, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.connectionStore != nil
		}},
	}
}

// selfServiceEndpointCandidates approximates mountCoreOAuthOIDC's
// unauthenticated password-reset/signup block plus mountSelfServiceProfile +
// mountSelfServiceCredentials. Some deeply-nested sub-conditions (e.g. the
// TOTPEnrollmentWriter type assertion, signup's verification-mode branch)
// are simplified to their outer store check — the inventory can show a
// self-service sub-route as live in a narrow misconfiguration where the real
// route is not (never the reverse: SelfService off always hides all of
// these). Good enough for "what surface is exposed", not a byte-exact mirror.
func selfServiceEndpointCandidates() []endpointCandidate {
	on := func(cond func(s *Server) bool) func(s *Server) bool {
		return func(s *Server) bool { return s.selfServiceGateOn() && cond(s) }
	}
	hasBoth := func(a, b func(s *Server) bool) func(s *Server) bool {
		return func(s *Server) bool { return a(s) && b(s) }
	}
	return []endpointCandidate{
		{endpointInfo{http.MethodPost, PathForgotPassword, "self_service"}, on(func(s *Server) bool {
			return s.passwordResetStore != nil && s.passwordCredentialStore != nil
		})},
		{endpointInfo{http.MethodPost, PathResetPassword, "self_service"}, on(func(s *Server) bool {
			return s.passwordResetStore != nil && s.passwordCredentialStore != nil
		})},
		{endpointInfo{http.MethodPost, PathSignup, "self_service"}, on(func(s *Server) bool {
			return s.signupEnabled && s.userProvider != nil && s.passwordCredentialStore != nil
		})},
		{endpointInfo{http.MethodPost, PathVerifyEmail, "self_service"}, on(func(s *Server) bool {
			return s.signupEnabled && s.emailVerificationStore != nil
		})},
		{endpointInfo{http.MethodGet, PathMyPermissions, "self_service"}, func(s *Server) bool { return s.selfServiceGateOn() }},
		{endpointInfo{http.MethodGet, PathMySessions, "self_service"}, on(func(s *Server) bool { return s.sessionMgr != nil })},
		{endpointInfo{http.MethodGet, PathMyConsents, "self_service"}, on(func(s *Server) bool { return s.consentStore != nil })},
		{endpointInfo{http.MethodGet, PathMyOrganizations, "self_service"}, on(func(s *Server) bool { return s.tenantUserStore != nil })},
		{endpointInfo{http.MethodGet, PathMe, "self_service"}, on(func(s *Server) bool { return s.userProvider != nil })},
		{endpointInfo{http.MethodPost, PathMyPassword, "self_service"}, on(func(s *Server) bool { return s.passwordCredentialStore != nil })},
		{endpointInfo{http.MethodGet, PathMyMFA, "self_service"}, on(func(s *Server) bool { return s.mfaEnrollmentStore != nil })},
		{endpointInfo{http.MethodPost, PathMyWebAuthnRegisterBegin, "self_service"}, on(func(s *Server) bool { return s.webauthnRegistrar != nil })},
		{endpointInfo{http.MethodGet, PathMyDataExport, "self_service"}, on(func(s *Server) bool { return s.dataExporter != nil })},
		{endpointInfo{http.MethodPost, PathMyAccountErase, "self_service"}, on(func(s *Server) bool { return s.accountEraser != nil })},
		{endpointInfo{http.MethodPost, PathMyEmailChange, "self_service"}, on(hasBoth(
			func(s *Server) bool { return s.emailChangeStore != nil && s.emailChangeSender != nil },
			func(s *Server) bool { return s.userProvider != nil },
		))},
	}
}

// adminAPIEndpointCandidates lists the /api/v1/admin/* (+ the co-mounted
// /api/v1/clients/:id) routes, each gated on AdminAPI AND its own store —
// mirrors mountAdminSurface's group-level gate ANDed with the per-block
// conditions above / in server_federation.go.
func adminAPIEndpointCandidates() []endpointCandidate {
	prefix := PathAPIPrefix
	on := func(cond func(s *Server) bool) func(s *Server) bool {
		return func(s *Server) bool { return s.adminAPIGateOn() && cond(s) }
	}
	return []endpointCandidate{
		{endpointInfo{http.MethodGet, prefix + PathClientByID, "admin_api"}, func(s *Server) bool { return s.adminAPIGateOn() }},
		{endpointInfo{http.MethodGet, prefix + PathAdminEndpoints, "admin_api"}, func(s *Server) bool { return s.adminAPIGateOn() }},
		{endpointInfo{http.MethodGet, prefix + PathAuditEvents, "admin_api"}, on(func(s *Server) bool { return s.auditAPI && s.auditor != nil })},
		{endpointInfo{http.MethodGet, prefix + PathNetPolicies, "admin_api"}, on(func(s *Server) bool { return s.netAPI && s.netStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathTenantUsage, "admin_api"}, on(func(s *Server) bool { return s.usageAggregator != nil })},
		{endpointInfo{http.MethodPost, prefix + PathBackup, "admin_api"}, on(func(s *Server) bool { return len(s.backupSources) > 0 })},
		{endpointInfo{http.MethodGet, prefix + PathAdminTokens, "admin_api"}, on(func(s *Server) bool { return s.adminTokenStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminSessions, "admin_api"}, on(func(s *Server) bool { return s.sessionMgr != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminUserConsents, "admin_api"}, on(func(s *Server) bool { return s.consentStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminUserMFA, "admin_api"}, on(func(s *Server) bool { return s.mfaEnrollmentStore != nil })},
		{endpointInfo{http.MethodPost, prefix + PathAdminUserPassword, "admin_api"}, on(func(s *Server) bool { return s.passwordCredentialStore != nil })},
		{endpointInfo{http.MethodPost, prefix + PathAdminUserEmail, "admin_api"}, on(func(s *Server) bool { return s.userProvider != nil })},
		{endpointInfo{http.MethodDelete, prefix + PathAdminUserDeviceSecrets, "admin_api"}, on(func(s *Server) bool { return s.deviceSecretStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminUserPasswordResetTokens, "admin_api"}, on(func(s *Server) bool { return s.passwordResetStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminUserEmailChangeTokens, "admin_api"}, on(func(s *Server) bool { return s.emailChangeStore != nil })},
		{endpointInfo{http.MethodPost, prefix + PathAdminAccountLockoutClear, "admin_api"}, on(func(s *Server) bool { return s.accountLockout != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminConnections, "admin_api"}, on(func(s *Server) bool { return s.connectionStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminTenantMembers, "admin_api"}, on(func(s *Server) bool { return s.tenantUserStore != nil })},
		{endpointInfo{http.MethodPost, prefix + PathAdminTenantInvitations, "admin_api"}, on(func(s *Server) bool { return s.invitationStore != nil })},
		{endpointInfo{http.MethodGet, PathAuthzPolicyBundle, "admin_api"}, on(func(s *Server) bool { return s.permissions != nil })},
		{endpointInfo{http.MethodGet, PathStorageHealth, "admin_api"}, on(func(s *Server) bool { return len(s.storageHealthSources) > 0 })},
	}
}

// endpointCandidates is the full table the inventory endpoint filters.
// Rebuilt per call (cheap — a few dozen struct literals) rather than a
// package-level var so it never risks aliasing mutable predicate state.
func endpointCandidates() []endpointCandidate {
	var all []endpointCandidate
	all = append(all, coreEndpointCandidates()...)
	all = append(all, gatedProtocolEndpointCandidates()...)
	all = append(all, selfServiceEndpointCandidates()...)
	all = append(all, adminAPIEndpointCandidates()...)
	return all
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
