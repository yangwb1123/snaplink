package auditreport

import "github.com/snaplink/sso/platform/audit"

// controlAreaDef is the static definition of one evidence bucket: a
// code, a human name, and the fixed vocabulary of audit.EventType
// values that belong to it.
type controlAreaDef struct {
	code       string
	name       string
	eventTypes []audit.EventType
}

// controlAreaDefs is the illustrative Trust-Services-Criteria cross
// reference — see the package doc's MANDATORY disclaimer: this is an
// ILLUSTRATIVE MECHANICAL cross-reference, NOT a vetted SOC2 control
// mapping. It is a data table, not a switch, so BuildSOC2Report's
// bucketing loop stays a single small function regardless of catalogue
// size, and so drift-test.go can walk it without a type switch to keep
// in sync.
//
// Each audit.EventType MUST appear in AT MOST one entry — enforced by
// TestControlAreaDefs_NoEventTypeClaimedTwice — so a report's per-area
// counts never double-count a single event. Data-subject-request event
// types are filed under "Privacy" rather than "CC6.3" (even the
// EventAdmin* ones) to avoid double counting a subject-export/erase
// action under both the admin-actions and privacy buckets.
//
// auditspi/event_types_admin.go currently declares 42 EventAdmin* consts:
// 38 land in CC6.3 below, EventAdminSigningKeyRotated lands in CC6.6
// (cryptographic key management, not a generic privileged action), and
// EventAdminSubjectExported/EventAdminSubjectErased/EventAdminTenantExported
// land in Privacy. This count is a manual cross-check for a human reading
// this file — the
// enforced source of truth is drift_test.go's
// TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized, which fails
// CI (not just a stale comment) the moment a new EventAdmin* const is
// added here without a bucket decision.
var controlAreaDefs = []controlAreaDef{
	{
		code: "CC6.1",
		name: "Access control",
		eventTypes: []audit.EventType{
			audit.EventLogin,
			audit.EventLoginFailure,
			audit.EventLogout,
			audit.EventClientAccess,
			audit.EventPermissionQuery,
		},
	},
	{
		code: "CC6.7",
		name: "Multi-factor authentication",
		eventTypes: []audit.EventType{
			audit.EventMFARequired,
			audit.EventMFASuccess,
			audit.EventMFAFailure,
			audit.EventTOTPEnrolled,
			audit.EventTOTPEnrollFailed,
			audit.EventWebAuthnRegistered,
			audit.EventWebAuthnAttestationDenied,
			audit.EventRecoveryCodesRegenerated,
		},
	},
	{
		code: "CC6.3",
		name: "Privileged and administrative actions",
		eventTypes: []audit.EventType{
			audit.EventAdminClientCreated,
			audit.EventAdminClientUpdated,
			audit.EventAdminClientDeleted,
			audit.EventAdminClientSecretRotated,
			audit.EventAdminUserCreated,
			audit.EventAdminUserUpdated,
			audit.EventAdminUserDeleted,
			audit.EventAdminTokenRevoked,
			audit.EventAdminTempTokenIssued,
			audit.EventAdminConsentRevoked,
			audit.EventAdminMFAFactorRemoved,
			audit.EventAdminRecoveryCodesReset,
			audit.EventAdminPasswordReset,
			audit.EventAdminDeviceSecretsRevoked,
			audit.EventAdminPasswordResetTokensRevoked,
			audit.EventAdminEmailChangeTokensRevoked,
			audit.EventAdminUserEmailChanged,
			audit.EventAdminAccountUnlocked,
			audit.EventAdminConnectionUpserted,
			audit.EventAdminConnectionDeleted,
			audit.EventAdminConnectionDomainVerified,
			audit.EventAdminConnectionProbed,
			audit.EventAdminTenantMemberAdded,
			audit.EventAdminTenantMemberRemoved,
			audit.EventAdminRoleAdded,
			audit.EventAdminRoleUpdated,
			audit.EventAdminRoleRemoved,
			audit.EventAdminRoleAssigned,
			audit.EventAdminRoleUnassigned,
			audit.EventAdminMenusUpdated,
			audit.EventAdminTenantCreated,
			audit.EventAdminTenantUpdated,
			audit.EventAdminTenantDeleted,
			audit.EventAdminTenantStatusChanged,
			audit.EventAdminDomainCreated,
			audit.EventAdminDomainUpdated,
			audit.EventAdminDomainDeleted,
			audit.EventAdminGRPCCalled,
		},
	},
	{
		code: "CC6.6",
		name: "Cryptographic key management",
		eventTypes: []audit.EventType{
			audit.EventSigningKeyRotated,
			audit.EventAdminSigningKeyRotated,
			audit.EventSigningKeyRotationCoordinated,
			audit.EventSigningKeyAggregationDegraded,
			audit.EventSigningKeyAggregationRecovered,
			audit.EventSigningKeyAdoptionErrorsTotal,
		},
	},
	{
		code: "CC7.2",
		name: "Anomaly and lockout monitoring",
		eventTypes: []audit.EventType{
			audit.EventAccountLocked,
			audit.EventAnomalyDetected,
			audit.EventRefreshTokenReuse,
			audit.EventRefreshRotationVelocityExceeded,
			audit.EventFAPIComplianceViolation,
		},
	},
	{
		code: "Privacy",
		name: "Data subject requests",
		eventTypes: []audit.EventType{
			audit.EventAdminSubjectExported,
			audit.EventAdminSubjectErased,
			audit.EventAdminTenantExported,
			audit.EventSubjectDataExported,
			audit.EventSubjectSelfErased,
		},
	},
}
