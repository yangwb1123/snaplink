package auditspi

// Admin control-plane mutation events. Every mutating RPC on the
// ClientAdmin / UserAdmin / TokenAdmin / PermissionAdmin services emits
// one of these. ActorID is the admin who issued the call; Reason
// carries "target=<resource>" for easy auditing.
const (
	EventAdminClientCreated       EventType = "admin_client_created"
	EventAdminClientUpdated       EventType = "admin_client_updated"
	EventAdminClientDeleted       EventType = "admin_client_deleted"
	EventAdminClientSecretRotated EventType = "admin_client_secret_rotated"
	// EventAdminClientApproved / EventAdminClientRejected are emitted by the
	// developer-app registration review workflow (ClientAdminService.Approve
	// / Reject) — distinct from the generic EventAdminClientUpdated so an
	// operator's audit trail can tell "a pending registration was reviewed"
	// apart from an ordinary field edit. Approve flips Active to true;
	// Reject deletes the (never-activated) client outright, so its metadata
	// carries the name captured just before deletion.
	EventAdminClientApproved EventType = "admin_client_approved"
	EventAdminClientRejected EventType = "admin_client_rejected"
	EventAdminUserCreated    EventType = "admin_user_created"
	EventAdminUserUpdated    EventType = "admin_user_updated"
	EventAdminUserDeleted    EventType = "admin_user_deleted"
	// EventAdminUserLifecycleChanged is emitted for every applied user-lifecycle
	// state transition — both operator-driven (POST /admin/users/:id/lifecycle,
	// ActorID = admin) and the auto-deprovisioning sweep (ActorID = "system").
	// Metadata carries target_user, from_state, to_state, and (when supplied) a
	// reason, so a single record answers "who moved which account, whither, and
	// why".
	EventAdminUserLifecycleChanged       EventType = "admin_user_lifecycle_changed"
	EventAdminTokenRevoked               EventType = "admin_token_revoked"
	EventAdminTempTokenIssued            EventType = "admin_temp_token_issued"
	EventAdminConsentRevoked             EventType = "admin_consent_revoked"
	EventAdminMFAFactorRemoved           EventType = "admin_mfa_factor_removed"
	EventAdminRecoveryCodesReset         EventType = "admin_recovery_codes_reset"
	EventAdminPasswordReset              EventType = "admin_password_reset"
	EventAdminDeviceSecretsRevoked       EventType = "admin_device_secrets_revoked"
	EventAdminPasswordResetTokensRevoked EventType = "admin_password_reset_tokens_revoked"
	EventAdminEmailChangeTokensRevoked   EventType = "admin_email_change_tokens_revoked"
	EventAdminRefreshTokensRevoked       EventType = "admin_refresh_tokens_revoked"
	EventAdminUserEmailChanged           EventType = "admin_user_email_changed"
	EventAdminAccountUnlocked            EventType = "admin_account_unlocked"
	EventAdminConnectionUpserted         EventType = "admin_connection_upserted"
	EventAdminConnectionDeleted          EventType = "admin_connection_deleted"
	EventAdminConnectionDomainVerified   EventType = "admin_connection_domain_verified"
	// EventAdminConnectionProbed is emitted by the admin-triggered reachability
	// probe (POST .../connections/:id/probe) on EVERY attempt, success or
	// failure — the outcome rides in the health_status meta field, not the
	// event type, so the SIEM/report-side vocabulary stays fixed regardless of
	// how many health states this feature grows.
	EventAdminConnectionProbed    EventType = "admin_connection_probed"
	EventAdminTenantMemberAdded   EventType = "admin_tenant_member_added"
	EventAdminTenantMemberRemoved EventType = "admin_tenant_member_removed"
	EventAdminRoleAdded           EventType = "admin_role_added"
	EventAdminRoleUpdated         EventType = "admin_role_updated"
	EventAdminRoleRemoved         EventType = "admin_role_removed"
	EventAdminRoleAssigned        EventType = "admin_role_assigned"
	EventAdminRoleUnassigned      EventType = "admin_role_unassigned"
	EventAdminMenusUpdated        EventType = "admin_menus_updated"
	EventAdminResourceRegistered  EventType = "admin_resource_registered"
	EventAdminResourceRemoved     EventType = "admin_resource_removed"
	EventAdminTenantCreated       EventType = "admin_tenant_created"
	EventAdminTenantUpdated       EventType = "admin_tenant_updated"
	EventAdminTenantDeleted       EventType = "admin_tenant_deleted"
	EventAdminTenantStatusChanged EventType = "admin_tenant_status_changed"
	EventAdminDomainCreated       EventType = "admin_domain_created"
	EventAdminDomainUpdated       EventType = "admin_domain_updated"
	EventAdminDomainDeleted       EventType = "admin_domain_deleted"
	EventAdminSubjectExported     EventType = "admin_subject_exported"
	EventAdminSubjectErased       EventType = "admin_subject_erased"
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
	// EventAdminTenantExported is emitted by the admin tenant-export endpoint
	// (offboarding/environment-migration bundle) — the tenant-scoped sibling
	// of EventAdminSubjectExported, filed in the same Privacy control area
	// (see auditreport/control_areas.go) since both are bulk personal-data
	// export actions, not generic admin CRUD.
	EventAdminTenantExported EventType = "admin_tenant_exported"
	// EventAdminSigningKeyRotated is emitted by the KeyAdmin RotateSigningKey
	// RPC for an operator-initiated (on-demand) rotation. The scheduled loop
	// keeps EventSigningKeyRotated; this admin-namespaced variant carries the
	// actor so a break-glass rotation is attributable in the audit trail.
	EventAdminSigningKeyRotated EventType = "admin_signing_key_rotated"
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
	// EventAdminCryptoKeyCompromised is emitted by
	// POST /api/v1/admin/crypto/keys/{id}/compromise: an operator declared a
	// catalogued cryptographic key leaked. Bookkeeping/alerting ONLY — see
	// platform/lifecycle/cryptoinventory's package doc; the actual key
	// retirement (when one is triggered) runs through the owning concern's own
	// mechanism, not this event. Metadata carries the compliance evidence
	// chain: crypto_key_id, crypto_key_reason, crypto_key_source.
	EventAdminCryptoKeyCompromised EventType = "admin_crypto_key_compromised"
	// Generic event/webhook egress engine (platform/lifecycle/webhook) subscription
	// lifecycle — emitted by POST/DELETE
	// /api/v1/admin/webhooks/subscriptions[/:id].
	EventAdminWebhookSubscriptionCreated EventType = "admin_webhook_subscription_created"
	EventAdminWebhookSubscriptionDeleted EventType = "admin_webhook_subscription_deleted"
	// Generic change-approval workflow lifecycle events (platform/lifecycle/admingovernance,
	// POST /api/v1/admin/changes and .../{id}/approve|reject). Metadata carries
	// change_id, action_type, proposed_by, and — from Approved onward —
	// approved_by, mirroring the break-glass evidence chain's "who did what,
	// when" shape.
	EventAdminChangeProposed    EventType = "admin_change_proposed"
	EventAdminChangeApproved    EventType = "admin_change_approved"
	EventAdminChangeRejected    EventType = "admin_change_rejected"
	EventAdminChangeApplied     EventType = "admin_change_applied"
	EventAdminChangeApplyFailed EventType = "admin_change_apply_failed"
	// EventAdminConfigApplied / EventAdminConfigRolledBack are emitted by
	// POST /api/v1/admin/config/apply and .../rollback
	// (platform/configaudit.HandleApply/HandleRollback — the declared
	// peer-config baseline write path). Metadata carries the evidence chain:
	// apply_id (the new baseline version id), peer_digest (the verified peer
	// config fingerprint), and prev_id when a predecessor exists. Metadata
	// ONLY — never snapshot content: a config snapshot may carry
	// secret-shaped leaves, and the audit trail must never echo them.
	EventAdminConfigApplied    EventType = "admin_config_applied"
	EventAdminConfigRolledBack EventType = "admin_config_rolled_back"
	// Canary lifecycle events carry identifiers and health outcome metadata,
	// never the candidate snapshot.
	EventConfigCanaryStarted    EventType = "config_canary_started"
	EventConfigCanaryConfirmed  EventType = "config_canary_confirmed"
	EventConfigCanaryRolledBack EventType = "config_canary_rolled_back"
	// EventAdminWriteQuotaExceeded / EventAdminIPDenied are emitted by
	// AdminMiddleware when the opt-in write-quota or IP/geo allowlist gate
	// (platform/lifecycle/admingovernance) blocks a request, when an audit Recorder is
	// wired via SetAuditRecorder. Governance/observability only — neither
	// gate depends on the audit event landing.
	EventAdminWriteQuotaExceeded EventType = "admin_write_quota_exceeded"
	EventAdminIPDenied           EventType = "admin_ip_denied"
)
