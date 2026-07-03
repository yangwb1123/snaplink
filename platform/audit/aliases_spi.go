package audit

// The audit SPI data types (Event + the EventType catalogue, Outcome, Query, the
// Sink interface, ErrorHandler, ErrEventNotFound and the NewEventID helper) live
// in the auditspi leaf so this directory stays within the per-directory
// file-count budget and so the four stateless sink backends can live in the
// auditsink leaf without an import cycle. auditspi is dependency-free (stdlib
// only). These aliases preserve the historical audit.* import surface unchanged
// for the Recorder, the in-package sinks, and all external consumers; type
// aliases keep interface/struct identity intact.

import "github.com/snaplink/sso/platform/audit/auditspi"

type (
	ErrorHandler = auditspi.ErrorHandler
	Event        = auditspi.Event
	EventType    = auditspi.EventType
	Outcome      = auditspi.Outcome
	Query        = auditspi.Query
	Sink         = auditspi.Sink
)

const (
	DefaultQueryLimit                    = auditspi.DefaultQueryLimit
	EventAccountLocked                   = auditspi.EventAccountLocked
	EventAdminAccountUnlocked            = auditspi.EventAdminAccountUnlocked
	EventAdminClientCreated              = auditspi.EventAdminClientCreated
	EventAdminClientDeleted              = auditspi.EventAdminClientDeleted
	EventAdminClientSecretRotated        = auditspi.EventAdminClientSecretRotated
	EventAdminClientUpdated              = auditspi.EventAdminClientUpdated
	EventAdminConnectionDeleted          = auditspi.EventAdminConnectionDeleted
	EventAdminConnectionUpserted         = auditspi.EventAdminConnectionUpserted
	EventAdminConsentRevoked             = auditspi.EventAdminConsentRevoked
	EventAdminDeviceSecretsRevoked       = auditspi.EventAdminDeviceSecretsRevoked
	EventAdminDomainCreated              = auditspi.EventAdminDomainCreated
	EventAdminDomainDeleted              = auditspi.EventAdminDomainDeleted
	EventAdminDomainUpdated              = auditspi.EventAdminDomainUpdated
	EventAdminEmailChangeTokensRevoked   = auditspi.EventAdminEmailChangeTokensRevoked
	EventAdminMFAFactorRemoved           = auditspi.EventAdminMFAFactorRemoved
	EventAdminMenusUpdated               = auditspi.EventAdminMenusUpdated
	EventAdminPasswordReset              = auditspi.EventAdminPasswordReset
	EventAdminPasswordResetTokensRevoked = auditspi.EventAdminPasswordResetTokensRevoked
	EventAdminRoleAdded                  = auditspi.EventAdminRoleAdded
	EventAdminRoleAssigned               = auditspi.EventAdminRoleAssigned
	EventAdminRoleRemoved                = auditspi.EventAdminRoleRemoved
	EventAdminRoleUnassigned             = auditspi.EventAdminRoleUnassigned
	EventAdminRoleUpdated                = auditspi.EventAdminRoleUpdated
	EventAdminSubjectErased              = auditspi.EventAdminSubjectErased
	EventAdminSubjectExported            = auditspi.EventAdminSubjectExported
	EventAdminGRPCCalled                 = auditspi.EventAdminGRPCCalled
	EventAdminTempTokenIssued            = auditspi.EventAdminTempTokenIssued
	EventAdminTenantCreated              = auditspi.EventAdminTenantCreated
	EventAdminTenantDeleted              = auditspi.EventAdminTenantDeleted
	EventAdminTenantMemberAdded          = auditspi.EventAdminTenantMemberAdded
	EventAdminTenantMemberRemoved        = auditspi.EventAdminTenantMemberRemoved
	EventAdminTenantStatusChanged        = auditspi.EventAdminTenantStatusChanged
	EventAdminTenantUpdated              = auditspi.EventAdminTenantUpdated
	EventAdminTokenRevoked               = auditspi.EventAdminTokenRevoked
	EventAdminUserCreated                = auditspi.EventAdminUserCreated
	EventAdminUserDeleted                = auditspi.EventAdminUserDeleted
	EventAdminUserEmailChanged           = auditspi.EventAdminUserEmailChanged
	EventAdminUserUpdated                = auditspi.EventAdminUserUpdated
	EventAnomalyDetected                 = auditspi.EventAnomalyDetected
	EventBootstrapLockAcquired           = auditspi.EventBootstrapLockAcquired
	EventBootstrapLockContended          = auditspi.EventBootstrapLockContended
	EventBootstrapLockLost               = auditspi.EventBootstrapLockLost
	EventBootstrapLockReleased           = auditspi.EventBootstrapLockReleased
	EventBootstrapStepApplied            = auditspi.EventBootstrapStepApplied
	EventBootstrapStepFailed             = auditspi.EventBootstrapStepFailed
	EventBootstrapStepSkipped            = auditspi.EventBootstrapStepSkipped
	EventCAEPSetSent                     = auditspi.EventCAEPSetSent
	EventCIBAApproved                    = auditspi.EventCIBAApproved
	EventCIBAAuthRequest                 = auditspi.EventCIBAAuthRequest
	EventCIBADenied                      = auditspi.EventCIBADenied
	EventCIBAPingFailed                  = auditspi.EventCIBAPingFailed
	EventCallbackFailure                 = auditspi.EventCallbackFailure
	EventClientAccess                    = auditspi.EventClientAccess
	EventClientDeleted                   = auditspi.EventClientDeleted
	EventClientRegistered                = auditspi.EventClientRegistered
	EventClientUpdated                   = auditspi.EventClientUpdated
	EventCodeSent                        = auditspi.EventCodeSent
	EventConsentDenied                   = auditspi.EventConsentDenied
	EventConsentGranted                  = auditspi.EventConsentGranted
	EventConsentRevoked                  = auditspi.EventConsentRevoked
	EventDeviceCodeApproved              = auditspi.EventDeviceCodeApproved
	EventDeviceCodeDenied                = auditspi.EventDeviceCodeDenied
	EventDeviceCodeIssued                = auditspi.EventDeviceCodeIssued
	EventEmailChangeRequested            = auditspi.EventEmailChangeRequested
	EventEmailChanged                    = auditspi.EventEmailChanged
	EventFAPIComplianceViolation         = auditspi.EventFAPIComplianceViolation
	EventFeatureGatesDisabled            = auditspi.EventFeatureGatesDisabled
	EventIDTokenIssued                   = auditspi.EventIDTokenIssued
	EventInvalidationBusDegraded         = auditspi.EventInvalidationBusDegraded
	EventInvalidationBusReconnected      = auditspi.EventInvalidationBusReconnected
	EventInvitationAccepted              = auditspi.EventInvitationAccepted
	EventInvitationRevoked               = auditspi.EventInvitationRevoked
	EventInvitationSent                  = auditspi.EventInvitationSent
	EventLogin                           = auditspi.EventLogin
	EventLoginFailure                    = auditspi.EventLoginFailure
	EventLogout                          = auditspi.EventLogout
	EventLogoutNotified                  = auditspi.EventLogoutNotified
	EventMFAFailure                      = auditspi.EventMFAFailure
	EventMFARequired                     = auditspi.EventMFARequired
	EventMFASuccess                      = auditspi.EventMFASuccess
	EventNativeSSOExchange               = auditspi.EventNativeSSOExchange
	EventNativeSSOExchangeFailure        = auditspi.EventNativeSSOExchangeFailure
	EventNetPolicyApply                  = auditspi.EventNetPolicyApply
	EventNetPolicyDelete                 = auditspi.EventNetPolicyDelete
	EventOrgLeft                         = auditspi.EventOrgLeft
	EventOrgMemberAutoProvisioned        = auditspi.EventOrgMemberAutoProvisioned
	EventPartialRevokeFailure            = auditspi.EventPartialRevokeFailure
	EventPasswordCompromised             = auditspi.EventPasswordCompromised
	EventPasswordResetCompleted          = auditspi.EventPasswordResetCompleted
	EventPasswordResetFailed             = auditspi.EventPasswordResetFailed
	EventPasswordResetRequested          = auditspi.EventPasswordResetRequested
	EventPasswordWeak                    = auditspi.EventPasswordWeak
	EventPermissionQuery                 = auditspi.EventPermissionQuery
	EventRefreshRotationVelocityExceeded = auditspi.EventRefreshRotationVelocityExceeded
	EventRefreshTokenIssued              = auditspi.EventRefreshTokenIssued
	EventRefreshTokenReuse               = auditspi.EventRefreshTokenReuse
	EventReleaseDeleted                  = auditspi.EventReleaseDeleted
	EventReleasePinned                   = auditspi.EventReleasePinned
	EventReleaseRegistered               = auditspi.EventReleaseRegistered
	EventReleaseRolledBack               = auditspi.EventReleaseRolledBack
	EventSPIFFEJWTSVIDAccepted           = auditspi.EventSPIFFEJWTSVIDAccepted
	EventSSFSetReceived                  = auditspi.EventSSFSetReceived
	EventSelfRegistered                  = auditspi.EventSelfRegistered
	EventSigningKeyAdoptionErrorsTotal   = auditspi.EventSigningKeyAdoptionErrorsTotal
	EventSigningKeyAggregationDegraded   = auditspi.EventSigningKeyAggregationDegraded
	EventSigningKeyAggregationRecovered  = auditspi.EventSigningKeyAggregationRecovered
	EventSigningKeyRotated               = auditspi.EventSigningKeyRotated
	EventSigningKeyRotationCoordinated   = auditspi.EventSigningKeyRotationCoordinated
	EventSnapshotDeleted                 = auditspi.EventSnapshotDeleted
	EventSnapshotExported                = auditspi.EventSnapshotExported
	EventSnapshotRestored                = auditspi.EventSnapshotRestored
	EventSubjectDataExported             = auditspi.EventSubjectDataExported
	EventSubjectSelfErased               = auditspi.EventSubjectSelfErased
	EventTOTPEnrollFailed                = auditspi.EventTOTPEnrollFailed
	EventTOTPEnrolled                    = auditspi.EventTOTPEnrolled
	EventTenantSessionsRevoked           = auditspi.EventTenantSessionsRevoked
	EventTenantTokensRevoked             = auditspi.EventTenantTokensRevoked
	EventTokenIssued                     = auditspi.EventTokenIssued
	EventTokenRevoked                    = auditspi.EventTokenRevoked
	EventWebAuthnAttestationDenied       = auditspi.EventWebAuthnAttestationDenied
	EventWebAuthnRegistered              = auditspi.EventWebAuthnRegistered
	MaxQueryLimit                        = auditspi.MaxQueryLimit
	OutcomeFailure                       = auditspi.OutcomeFailure
	OutcomeSuccess                       = auditspi.OutcomeSuccess
)

var (
	ErrEventNotFound = auditspi.ErrEventNotFound
	NewEventID       = auditspi.NewEventID
)

// newEventID keeps the historical unexported call site working in this package.
var newEventID = auditspi.NewEventID
