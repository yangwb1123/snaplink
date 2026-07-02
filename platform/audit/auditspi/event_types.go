package auditspi

// EventType identifies the kind of event being recorded. Custom types are
// allowed — the constants below are the ones the sso package emits itself.
type EventType string

// Core authentication and token lifecycle events.
const (
	EventLogin           EventType = "login"
	EventLoginFailure    EventType = "login_failure"
	EventLogout          EventType = "logout"
	EventTokenIssued     EventType = "token_issued"
	EventTokenRevoked    EventType = "token_revoked"
	EventCodeSent        EventType = "code_sent"
	EventCallbackFailure EventType = "callback_failure"
	EventClientAccess    EventType = "client_access"
	EventPermissionQuery EventType = "permission_query"
)

// DCR (RFC 7591/7592) lifecycle events.
const (
	EventClientRegistered EventType = "client_registered"
	EventClientUpdated    EventType = "client_updated"
	EventClientDeleted    EventType = "client_deleted"
)

// Network policy events.
const (
	EventNetPolicyApply  EventType = "netpolicy_apply"
	EventNetPolicyDelete EventType = "netpolicy_delete"
)

// OIDC Back-Channel Logout 1.0 notification attempt.
const (
	EventLogoutNotified EventType = "logout_notified"
)

// Partial revoke failure — at least one TokenIssuer's Revoke returned an
// error during a bulk revoke while at least one other issuer succeeded.
const (
	EventPartialRevokeFailure EventType = "partial_revoke_failure"
)

// Tenant suspension revocation events.
const (
	EventTenantTokensRevoked   EventType = "tenant_tokens_revoked"
	EventTenantSessionsRevoked EventType = "tenant_sessions_revoked"
)

// Per-account lockout events.
const (
	EventAccountLocked EventType = "account_locked"
)

// MFA orchestration events.
const (
	EventMFARequired EventType = "mfa_required"
	EventMFASuccess  EventType = "mfa_success"
	EventMFAFailure  EventType = "mfa_failure"
)

// Anomaly detection events (off the request hot path).
const (
	EventAnomalyDetected EventType = "anomaly_detected"
)

// WebAuthn attestation events.
const (
	EventWebAuthnRegistered        EventType = "webauthn_registered"
	EventWebAuthnAttestationDenied EventType = "webauthn_attestation_denied"
)

// Password reset flow events.
const (
	EventPasswordResetRequested EventType = "password_reset_requested"
	EventPasswordResetCompleted EventType = "password_reset_completed"
	EventPasswordResetFailed    EventType = "password_reset_failed"
)

// TOTP enrollment events.
const (
	EventTOTPEnrolled     EventType = "mfa_totp_enrolled"
	EventTOTPEnrollFailed EventType = "mfa_totp_enroll_failed"
)

// MFA recovery-code events (self-service). Regeneration is the only
// self-service mutation worth auditing; redemption rides the existing
// mfa_success/mfa_failure events via the MFAProvider dispatch.
const (
	EventRecoveryCodesRegenerated EventType = "mfa_recovery_codes_regenerated"
)

// Trusted-device (remember-this-device) MFA-skip events (self-service +
// login-time). Trusted and revoked are user-initiated mutations of the
// grant itself; skipped fires on every LOGIN that used a live grant to
// bypass a risk-scorer step-up demand, so operators can distinguish
// "verified factor" from "trusted device" in the mfa_success-adjacent trail.
const (
	EventDeviceTrusted           EventType = "device_trusted"
	EventDeviceTrustRevoked      EventType = "device_trust_revoked"
	EventMFASkippedTrustedDevice EventType = "mfa_skipped_trusted_device"
)

// Consent lifecycle events (user-initiated).
const (
	EventConsentGranted EventType = "consent_granted"
	EventConsentRevoked EventType = "consent_revoked"
	EventConsentDenied  EventType = "consent_denied"
)

// Self-service registration and account management.
const (
	EventSelfRegistered      EventType = "self_registered"
	EventSubjectDataExported EventType = "subject_data_exported"
	EventSubjectSelfErased   EventType = "subject_self_erased"
)

// Email change flow events.
const (
	EventEmailChangeRequested EventType = "email_change_requested"
	EventEmailChanged         EventType = "email_changed"
)

// Organization membership events.
const (
	EventOrgLeft                  EventType = "org_left"
	EventOrgMemberAutoProvisioned EventType = "org_member_auto_provisioned"
	EventInvitationSent           EventType = "invitation_sent"
	EventInvitationAccepted       EventType = "invitation_accepted"
	EventInvitationRevoked        EventType = "invitation_revoked"
)

// Credential health signals (non-blocking login-time).
const (
	EventPasswordWeak        EventType = "password_weak"
	EventPasswordCompromised EventType = "password_compromised"
)

// SPIFFE JWT-SVID acceptance.
const (
	EventSPIFFEJWTSVIDAccepted EventType = "spiffe_jwt_svid_accepted"
)

// FAPI 2.0 compliance violations.
const (
	EventFAPIComplianceViolation EventType = "fapi_compliance_violation"
)

// Refresh token rotation security events.
const (
	EventRefreshTokenReuse               EventType = "refresh_token_reuse_detected"
	EventRefreshRotationVelocityExceeded EventType = "refresh_rotation_velocity_exceeded"
)

// OAuth/OIDC token lifecycle beyond the legacy EventTokenIssued.
const (
	EventRefreshTokenIssued EventType = "refresh_token_issued"
	EventIDTokenIssued      EventType = "id_token_issued"
	EventDeviceCodeIssued   EventType = "device_code_issued"
	EventDeviceCodeApproved EventType = "device_code_approved"
	EventDeviceCodeDenied   EventType = "device_code_denied"
)

// CIBA backchannel authentication events.
const (
	EventCIBAAuthRequest EventType = "ciba_auth_request"
	EventCIBAApproved    EventType = "ciba_approved"
	EventCIBADenied      EventType = "ciba_denied"
	EventCIBAPingFailed  EventType = "ciba_ping_failed"
)

// Native SSO exchange events.
const (
	EventNativeSSOExchange        EventType = "native_sso_exchange"
	EventNativeSSOExchangeFailure EventType = "native_sso_exchange_failure"
)

// KnownEventTypes is the set of every event type the SDK emits itself
// (across this file plus event_types_admin.go and event_types_system.go).
// It exists so operator-facing tooling — e.g. the audit webhook subscription
// wiring — can flag a mistyped event_types filter entry while still allowing
// unknown strings through (custom event types are legal per EventType's doc).
// It is a filter/UX aid ONLY and is never consulted on the record path.
var KnownEventTypes = map[EventType]struct{}{
	// core auth + token lifecycle
	EventLogin: {}, EventLoginFailure: {}, EventLogout: {}, EventTokenIssued: {},
	EventTokenRevoked: {}, EventCodeSent: {}, EventCallbackFailure: {},
	EventClientAccess: {}, EventPermissionQuery: {},
	// DCR
	EventClientRegistered: {}, EventClientUpdated: {}, EventClientDeleted: {},
	// network policy
	EventNetPolicyApply: {}, EventNetPolicyDelete: {},
	// back-channel logout + partial revoke
	EventLogoutNotified: {}, EventPartialRevokeFailure: {},
	// tenant + lockout
	EventTenantTokensRevoked: {}, EventTenantSessionsRevoked: {}, EventAccountLocked: {},
	// MFA + anomaly
	EventMFARequired: {}, EventMFASuccess: {}, EventMFAFailure: {}, EventAnomalyDetected: {},
	// webauthn
	EventWebAuthnRegistered: {}, EventWebAuthnAttestationDenied: {},
	// password reset + TOTP enroll
	EventPasswordResetRequested: {}, EventPasswordResetCompleted: {}, EventPasswordResetFailed: {},
	EventTOTPEnrolled: {}, EventTOTPEnrollFailed: {},
	// MFA recovery-code regeneration (self-service)
	EventRecoveryCodesRegenerated: {},
	// trusted-device MFA-skip (self-service + login-time)
	EventDeviceTrusted: {}, EventDeviceTrustRevoked: {}, EventMFASkippedTrustedDevice: {},
	// consent
	EventConsentGranted: {}, EventConsentRevoked: {}, EventConsentDenied: {},
	// self-service + email change
	EventSelfRegistered: {}, EventSubjectDataExported: {}, EventSubjectSelfErased: {},
	EventEmailChangeRequested: {}, EventEmailChanged: {},
	// org membership
	EventOrgLeft: {}, EventOrgMemberAutoProvisioned: {}, EventInvitationSent: {},
	EventInvitationAccepted: {}, EventInvitationRevoked: {},
	// credential health + SPIFFE + FAPI
	EventPasswordWeak: {}, EventPasswordCompromised: {}, EventSPIFFEJWTSVIDAccepted: {},
	EventFAPIComplianceViolation: {},
	// refresh rotation + token lifecycle
	EventRefreshTokenReuse: {}, EventRefreshRotationVelocityExceeded: {},
	EventRefreshTokenIssued: {}, EventIDTokenIssued: {}, EventDeviceCodeIssued: {},
	EventDeviceCodeApproved: {}, EventDeviceCodeDenied: {},
	// CIBA + native SSO
	EventCIBAAuthRequest: {}, EventCIBAApproved: {}, EventCIBADenied: {}, EventCIBAPingFailed: {},
	EventNativeSSOExchange: {}, EventNativeSSOExchangeFailure: {},
	// admin control-plane (event_types_admin.go)
	EventAdminClientCreated: {}, EventAdminClientUpdated: {}, EventAdminClientDeleted: {},
	EventAdminClientSecretRotated: {}, EventAdminUserCreated: {}, EventAdminUserUpdated: {},
	EventAdminUserDeleted: {}, EventAdminTokenRevoked: {}, EventAdminTempTokenIssued: {},
	EventAdminConsentRevoked: {}, EventAdminMFAFactorRemoved: {}, EventAdminPasswordReset: {},
	EventAdminDeviceSecretsRevoked: {}, EventAdminPasswordResetTokensRevoked: {},
	EventAdminEmailChangeTokensRevoked: {}, EventAdminUserEmailChanged: {},
	EventAdminAccountUnlocked: {}, EventAdminConnectionUpserted: {}, EventAdminConnectionDeleted: {},
	EventAdminConnectionDomainVerified: {}, EventAdminRecoveryCodesReset: {},
	EventAdminTenantMemberAdded: {}, EventAdminTenantMemberRemoved: {}, EventAdminRoleAdded: {},
	EventAdminRoleUpdated: {}, EventAdminRoleRemoved: {}, EventAdminRoleAssigned: {},
	EventAdminRoleUnassigned: {}, EventAdminMenusUpdated: {}, EventAdminTenantCreated: {},
	EventAdminTenantUpdated: {}, EventAdminTenantDeleted: {}, EventAdminTenantStatusChanged: {},
	EventAdminDomainCreated: {}, EventAdminDomainUpdated: {}, EventAdminDomainDeleted: {},
	EventAdminSubjectExported: {}, EventAdminSubjectErased: {}, EventAdminGRPCCalled: {},
	EventAdminSigningKeyRotated: {},
	// system / platform (event_types_system.go)
	EventBootstrapStepApplied: {}, EventBootstrapStepSkipped: {}, EventBootstrapStepFailed: {},
	EventBootstrapLockAcquired: {}, EventBootstrapLockReleased: {}, EventBootstrapLockLost: {},
	EventBootstrapLockContended: {}, EventSnapshotExported: {}, EventSnapshotRestored: {},
	EventSnapshotDeleted: {}, EventReleaseRegistered: {}, EventReleasePinned: {},
	EventReleaseRolledBack: {}, EventReleaseDeleted: {}, EventSigningKeyRotated: {},
	EventSigningKeyAggregationDegraded: {}, EventSigningKeyAggregationRecovered: {},
	EventSigningKeyRotationCoordinated: {}, EventSigningKeyAdoptionErrorsTotal: {},
	EventCAEPSetSent: {}, EventSSFSetReceived: {},
	EventInvalidationBusDegraded: {}, EventInvalidationBusReconnected: {},
}
