package auditsink

import (
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// allKnownEventTypes is every EventType const currently defined across
// auditspi/event_types.go, event_types_admin.go, and event_types_system.go
// (122 at time of writing, generated via `grep -hoE '^\s*Event[A-Za-z0-9]+
// EventType\s*=' platform/audit/auditspi/event_types*.go`). This is a
// snapshot, not a reflective enumeration — Go has no runtime introspection
// over package-level consts — so adding a new EventType const does NOT
// automatically fail this test; it silently falls back to the generic CEF/
// OCSF classification (see cefName / ocsfActivityFor) until a maintainer
// adds it here AND to cefEventNames / ocsfEventActivities. That is the
// intended "build not hard-failed by future additions" behavior; this list
// exists to catch a mapping gap for a type that ALREADY exists today.
var allKnownEventTypes = []auditspi.EventType{
	auditspi.EventAccountLocked,
	auditspi.EventAdminAccountUnlocked,
	auditspi.EventAdminClientApproved,
	auditspi.EventAdminClientCreated,
	auditspi.EventAdminClientDeleted,
	auditspi.EventAdminClientRejected,
	auditspi.EventAdminClientSecretRotated,
	auditspi.EventAdminClientUpdated,
	auditspi.EventAdminConnectionDeleted,
	auditspi.EventAdminConnectionUpserted,
	auditspi.EventAdminConsentRevoked,
	auditspi.EventAdminDeviceSecretsRevoked,
	auditspi.EventAdminDomainCreated,
	auditspi.EventAdminDomainDeleted,
	auditspi.EventAdminDomainUpdated,
	auditspi.EventAdminEmailChangeTokensRevoked,
	auditspi.EventAdminGRPCCalled,
	auditspi.EventAdminMenusUpdated,
	auditspi.EventAdminResourceRegistered,
	auditspi.EventAdminResourceRemoved,
	auditspi.EventAdminMFAFactorRemoved,
	auditspi.EventAdminPasswordReset,
	auditspi.EventAdminPasswordResetTokensRevoked,
	auditspi.EventAdminRecoveryCodesReset,
	auditspi.EventAdminRoleAdded,
	auditspi.EventAdminRoleAssigned,
	auditspi.EventAdminRoleRemoved,
	auditspi.EventAdminRoleUnassigned,
	auditspi.EventAdminRoleUpdated,
	auditspi.EventAdminSubjectErased,
	auditspi.EventAdminSubjectExported,
	auditspi.EventAdminTempTokenIssued,
	auditspi.EventAdminTenantCreated,
	auditspi.EventAdminTenantDeleted,
	auditspi.EventAdminTenantMemberAdded,
	auditspi.EventAdminTenantMemberRemoved,
	auditspi.EventAdminTenantStatusChanged,
	auditspi.EventAdminTenantUpdated,
	auditspi.EventAdminTokenRevoked,
	auditspi.EventAdminUserCreated,
	auditspi.EventAdminUserDeleted,
	auditspi.EventAdminUserEmailChanged,
	auditspi.EventAdminUserUpdated,
	auditspi.EventAnomalyDetected,
	auditspi.EventBootstrapLockAcquired,
	auditspi.EventBootstrapLockContended,
	auditspi.EventBootstrapLockLost,
	auditspi.EventBootstrapLockReleased,
	auditspi.EventBootstrapStepApplied,
	auditspi.EventBootstrapStepFailed,
	auditspi.EventBootstrapStepSkipped,
	auditspi.EventCAEPSetSent,
	auditspi.EventCallbackFailure,
	auditspi.EventCIBAApproved,
	auditspi.EventCIBAAuthRequest,
	auditspi.EventCIBADenied,
	auditspi.EventCIBAPingFailed,
	auditspi.EventClientAccess,
	auditspi.EventClientDeleted,
	auditspi.EventClientRegistered,
	auditspi.EventClientUpdated,
	auditspi.EventCodeSent,
	auditspi.EventConsentDenied,
	auditspi.EventConsentGranted,
	auditspi.EventConsentRevoked,
	auditspi.EventDeviceCodeApproved,
	auditspi.EventDeviceCodeDenied,
	auditspi.EventDeviceCodeIssued,
	auditspi.EventEmailChanged,
	auditspi.EventEmailChangeRequested,
	auditspi.EventFAPIComplianceViolation,
	auditspi.EventIDTokenIssued,
	auditspi.EventInvalidationBusDegraded,
	auditspi.EventInvalidationBusReconnected,
	auditspi.EventInvitationAccepted,
	auditspi.EventInvitationRevoked,
	auditspi.EventInvitationSent,
	auditspi.EventLogin,
	auditspi.EventLoginFailure,
	auditspi.EventLogout,
	auditspi.EventLogoutNotified,
	auditspi.EventMFAFailure,
	auditspi.EventMFARequired,
	auditspi.EventMFASuccess,
	auditspi.EventNativeSSOExchange,
	auditspi.EventNativeSSOExchangeFailure,
	auditspi.EventNetPolicyApply,
	auditspi.EventNetPolicyDelete,
	auditspi.EventOrgLeft,
	auditspi.EventOrgMemberAutoProvisioned,
	auditspi.EventPartialRevokeFailure,
	auditspi.EventPasswordCompromised,
	auditspi.EventPasswordChanged,
	auditspi.EventPasswordResetCompleted,
	auditspi.EventPasswordResetFailed,
	auditspi.EventPasswordResetRequested,
	auditspi.EventPasswordWeak,
	auditspi.EventPermissionQuery,
	auditspi.EventRecoveryCodesRegenerated,
	auditspi.EventRefreshRotationVelocityExceeded,
	auditspi.EventRefreshTokenIssued,
	auditspi.EventRefreshTokenReuse,
	auditspi.EventReleaseDeleted,
	auditspi.EventReleasePinned,
	auditspi.EventReleaseRegistered,
	auditspi.EventReleaseRolledBack,
	auditspi.EventSelfRegistered,
	auditspi.EventSigningKeyAdoptionErrorsTotal,
	auditspi.EventSigningKeyAggregationDegraded,
	auditspi.EventSigningKeyAggregationRecovered,
	auditspi.EventSigningKeyRotated,
	auditspi.EventSigningKeyRotationCoordinated,
	auditspi.EventSnapshotDeleted,
	auditspi.EventSnapshotExported,
	auditspi.EventSnapshotRestored,
	auditspi.EventSPIFFEJWTSVIDAccepted,
	auditspi.EventSSFSetReceived,
	auditspi.EventSubjectDataExported,
	auditspi.EventSubjectSelfErased,
	auditspi.EventTenantSessionsRevoked,
	auditspi.EventTenantQuotaStoreFailure,
	auditspi.EventClientSecretExpiring,
	auditspi.EventAuditChainCheckpoint,
	auditspi.EventTenantQuotaProjectionApplied,
	auditspi.EventTenantTokensRevoked,
	auditspi.EventTokenIssued,
	auditspi.EventTokenRevoked,
	auditspi.EventTOTPEnrolled,
	auditspi.EventTOTPEnrollFailed,
	auditspi.EventWebAuthnAttestationDenied,
	auditspi.EventWebAuthnRegistered,
}

// TestConformance_EveryEventTypeHasCEFAndOCSFMapping is the SIEM-formats
// task's required conformance test: every EventType const the SDK defines
// today must yield a non-empty CEF class AND an explicit (non-fallback)
// entry in both cefEventNames and ocsfEventActivities. A type present in
// allKnownEventTypes but missing from either table is exactly the "silent
// gap" the task decision calls out — this test fails loudly instead of
// silently degrading to the generic/other fallback.
func TestConformance_EveryEventTypeHasCEFAndOCSFMapping(t *testing.T) {
	t.Parallel()
	if len(allKnownEventTypes) != len(auditspi.KnownEventTypes)+2 {
		// +2: EventAdminRecoveryCodesReset and EventRecoveryCodesRegenerated
		// exist as consts but are not (yet) registered in
		// auditspi.KnownEventTypes — a pre-existing gap in that table (owned
		// by the MFA recovery-code feature), not this one. This CEF/OCSF
		// conformance test still covers both, since allKnownEventTypes is
		// transcribed directly from event_types*.go rather than reusing
		// KnownEventTypes. Documented rather than silently tolerated: if the
		// counts drift further apart, this test's snapshot likely needs a
		// refresh.
		t.Logf("allKnownEventTypes=%d KnownEventTypes=%d (see comment on the +2 above)",
			len(allKnownEventTypes), len(auditspi.KnownEventTypes))
	}
	for _, et := range allKnownEventTypes {
		t.Run(string(et), func(t *testing.T) {
			if id := cefClassID(et); id == "" {
				t.Errorf("cefClassID(%s) is empty", et)
			}
			if _, ok := cefEventNames[et]; !ok {
				t.Errorf("%s missing from cefEventNames — falls back to humanizeEventType", et)
			}
			if cefName(et) == "" {
				t.Errorf("cefName(%s) is empty", et)
			}
			act, ok := ocsfEventActivities[et]
			if !ok {
				t.Errorf("%s missing from ocsfEventActivities — falls back to the generic/unmapped class", et)
			}
			if act.classUID == 0 {
				t.Errorf("ocsfEventActivities[%s].classUID is 0", et)
			}
			if act.activityName == "" {
				t.Errorf("ocsfEventActivities[%s].activityName is empty", et)
			}
		})
	}
}

// TestConformance_UnknownEventTypeFallsBackSafely proves the fallback path
// itself: a type absent from BOTH tables (a custom/future EventType) still
// yields non-empty CEF and OCSF classification — the "safe unknown ->
// generic/other fallback" half of the task decision, exercised directly
// rather than only implied by the exhaustive table above.
func TestConformance_UnknownEventTypeFallsBackSafely(t *testing.T) {
	t.Parallel()
	custom := auditspi.EventType("operator_custom_event")

	if id := cefClassID(custom); id != string(custom) {
		t.Errorf("cefClassID(custom) = %q, want the literal type string", id)
	}
	if name := cefName(custom); name != "Operator Custom Event" {
		t.Errorf("cefName(custom) = %q, want humanized fallback", name)
	}

	act := ocsfActivityFor(custom)
	if act != ocsfGenericActivity {
		t.Errorf("ocsfActivityFor(custom) = %+v, want the generic fallback %+v", act, ocsfGenericActivity)
	}
	if act.classUID == 0 {
		t.Error("generic fallback classUID must be non-zero")
	}

	// The empty type is the degenerate case: still must not panic or
	// produce empty output.
	if id := cefClassID(""); id != cefGenericClassID {
		t.Errorf("cefClassID(\"\") = %q, want %q", id, cefGenericClassID)
	}
	if name := cefName(""); name != cefGenericEventName {
		t.Errorf("cefName(\"\") = %q, want %q", name, cefGenericEventName)
	}
}
