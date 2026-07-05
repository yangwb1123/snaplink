package auditspi

// Admin control-plane mutation events. Every mutating RPC on the
// ClientAdmin / UserAdmin / TokenAdmin / PermissionAdmin services emits
// one of these. ActorID is the admin who issued the call; Reason
// carries "target=<resource>" for easy auditing.
const (
	EventAdminClientCreated              EventType = "admin_client_created"
	EventAdminClientUpdated              EventType = "admin_client_updated"
	EventAdminClientDeleted              EventType = "admin_client_deleted"
	EventAdminClientSecretRotated        EventType = "admin_client_secret_rotated"
	EventAdminUserCreated                EventType = "admin_user_created"
	EventAdminUserUpdated                EventType = "admin_user_updated"
	EventAdminUserDeleted                EventType = "admin_user_deleted"
	EventAdminTokenRevoked               EventType = "admin_token_revoked"
	EventAdminTempTokenIssued            EventType = "admin_temp_token_issued"
	EventAdminConsentRevoked             EventType = "admin_consent_revoked"
	EventAdminMFAFactorRemoved           EventType = "admin_mfa_factor_removed"
	EventAdminPasswordReset              EventType = "admin_password_reset"
	EventAdminDeviceSecretsRevoked       EventType = "admin_device_secrets_revoked"
	EventAdminPasswordResetTokensRevoked EventType = "admin_password_reset_tokens_revoked"
	EventAdminEmailChangeTokensRevoked   EventType = "admin_email_change_tokens_revoked"
	EventAdminUserEmailChanged           EventType = "admin_user_email_changed"
	EventAdminAccountUnlocked            EventType = "admin_account_unlocked"
	EventAdminConnectionUpserted         EventType = "admin_connection_upserted"
	EventAdminConnectionDeleted          EventType = "admin_connection_deleted"
	EventAdminTenantMemberAdded          EventType = "admin_tenant_member_added"
	EventAdminTenantMemberRemoved        EventType = "admin_tenant_member_removed"
	EventAdminRoleAdded                  EventType = "admin_role_added"
	EventAdminRoleUpdated                EventType = "admin_role_updated"
	EventAdminRoleRemoved                EventType = "admin_role_removed"
	EventAdminRoleAssigned               EventType = "admin_role_assigned"
	EventAdminRoleUnassigned             EventType = "admin_role_unassigned"
	EventAdminMenusUpdated               EventType = "admin_menus_updated"
	EventAdminTenantCreated              EventType = "admin_tenant_created"
	EventAdminTenantUpdated              EventType = "admin_tenant_updated"
	EventAdminTenantDeleted              EventType = "admin_tenant_deleted"
	EventAdminTenantStatusChanged        EventType = "admin_tenant_status_changed"
	EventAdminDomainCreated              EventType = "admin_domain_created"
	EventAdminDomainUpdated              EventType = "admin_domain_updated"
	EventAdminDomainDeleted              EventType = "admin_domain_deleted"
	EventAdminSubjectExported            EventType = "admin_subject_exported"
	EventAdminSubjectErased              EventType = "admin_subject_erased"
	// Break-glass lifecycle events. Every one carries the SOC 2 evidence
	// chain in Metadata: admin_id, target_user_id, admin_session_id,
	// break_glass_reason — "who acted as whom, when, and why".
	EventAdminBreakGlassCreated  EventType = "admin_break_glass_created"
	EventAdminBreakGlassApproved EventType = "admin_break_glass_approved"
	EventAdminBreakGlassRevoked  EventType = "admin_break_glass_revoked"
	EventAdminBreakGlassExpired  EventType = "admin_break_glass_expired"
	// EventAdminBreakGlassImpersonationStarted is emitted by
	// POST /api/v1/admin/break-glass/{id}/impersonate the moment a live
	// impersonation bearer is minted for the target user — the SOC 2 CC6.1
	// record that admin_id began acting AS target_user_id under this grant.
	EventAdminBreakGlassImpersonationStarted EventType = "admin_break_glass_impersonation_started"
	// EventAdminGRPCCalled is emitted by the gRPC admin audit interceptor
	// for every gated RPC. The interceptor auto-records actor, method,
	// duration, and grpc status — complementing the explicit per-RPC
	// events the handlers emit themselves.
	EventAdminGRPCCalled EventType = "admin_grpc_called"
	// EventAdminCredentialCompromised is emitted by
	// POST /api/v1/admin/credentials/{type}/compromise: an operator declared a
	// credential class leaked, force-rotating it off schedule with NO overlap.
	// Metadata carries the compliance evidence chain: credential_type,
	// credential_reason, credential_old_version, credential_new_version.
	EventAdminCredentialCompromised EventType = "admin_credential_compromised"
	// Generic change-approval workflow lifecycle events (domains/admingovernance,
	// POST /api/v1/admin/changes and .../{id}/approve|reject). Metadata carries
	// change_id, action_type, proposed_by, and — from Approved onward —
	// approved_by, mirroring the break-glass evidence chain's "who did what,
	// when" shape.
	EventAdminChangeProposed    EventType = "admin_change_proposed"
	EventAdminChangeApproved    EventType = "admin_change_approved"
	EventAdminChangeRejected    EventType = "admin_change_rejected"
	EventAdminChangeApplied     EventType = "admin_change_applied"
	EventAdminChangeApplyFailed EventType = "admin_change_apply_failed"
	// EventAdminWriteQuotaExceeded / EventAdminIPDenied are emitted by
	// AdminMiddleware when the opt-in write-quota or IP/geo allowlist gate
	// (domains/admingovernance) blocks a request, when an audit Recorder is
	// wired via SetAuditRecorder. Governance/observability only — neither
	// gate depends on the audit event landing.
	EventAdminWriteQuotaExceeded EventType = "admin_write_quota_exceeded"
	EventAdminIPDenied           EventType = "admin_ip_denied"
)
