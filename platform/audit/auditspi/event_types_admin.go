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
	EventAdminRecoveryCodesReset         EventType = "admin_recovery_codes_reset"
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
	// EventAdminGRPCCalled is emitted by the gRPC admin audit interceptor
	// for every gated RPC. The interceptor auto-records actor, method,
	// duration, and grpc status — complementing the explicit per-RPC
	// events the handlers emit themselves.
	EventAdminGRPCCalled EventType = "admin_grpc_called"
)
