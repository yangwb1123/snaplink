package selfservice

// The self-service handlers are split across cohesive leaf sub-packages so this
// directory stays within the per-directory file-count budget. The shared Deps
// surface lives in selfservicecore (imported by every leaf and by the kept
// handlers here); the account-management handlers live in selfserviceaccount.
// These aliases preserve the historical selfservice.* import surface unchanged
// for the Server wiring and any SDK consumer that calls the handlers directly.

import (
	"github.com/snaplink/sso/protocols/selfservice/selfserviceaccount"
	"github.com/snaplink/sso/protocols/selfservice/selfservicecore"
)

// Deps is the self-service capability surface (defined in selfservicecore).
type Deps = selfservicecore.Deps

// RecordSelfErase emits the account-erasure audit record (used by the kept
// data_export.go account-erase handler).
var RecordSelfErase = selfservicecore.RecordSelfErase

// Re-exported account-management handlers now implemented in selfserviceaccount.
var (
	HandleMe                     = selfserviceaccount.HandleMe
	HandleMyProfileUpdate        = selfserviceaccount.HandleMyProfileUpdate
	HandleChangeMyPassword       = selfserviceaccount.HandleChangeMyPassword
	HandleWebAuthnRegisterBegin  = selfserviceaccount.HandleWebAuthnRegisterBegin
	HandleWebAuthnRegisterFinish = selfserviceaccount.HandleWebAuthnRegisterFinish
	HandleMyConsents             = selfserviceaccount.HandleMyConsents
	HandleDeleteMyConsent        = selfserviceaccount.HandleDeleteMyConsent
	HandleMyOrganizations        = selfserviceaccount.HandleMyOrganizations
	HandleLeaveMyOrganization    = selfserviceaccount.HandleLeaveMyOrganization
	HandleAcceptInvitation       = selfserviceaccount.HandleAcceptInvitation

	// Delegated org-admin surface (w2.11): /me/organizations/:tenant_id/*.
	HandleOrgAdminListMembers      = selfserviceaccount.HandleOrgAdminListMembers
	HandleOrgAdminPutMember        = selfserviceaccount.HandleOrgAdminPutMember
	HandleOrgAdminRemoveMember     = selfserviceaccount.HandleOrgAdminRemoveMember
	HandleOrgAdminSendInvitation   = selfserviceaccount.HandleOrgAdminSendInvitation
	HandleOrgAdminListInvitations  = selfserviceaccount.HandleOrgAdminListInvitations
	HandleOrgAdminRevokeInvitation = selfserviceaccount.HandleOrgAdminRevokeInvitation
	HandleMyMFAFactors             = selfserviceaccount.HandleMyMFAFactors
	HandleDeleteMyMFAFactor        = selfserviceaccount.HandleDeleteMyMFAFactor
	HandleTOTPEnrollBegin          = selfserviceaccount.HandleTOTPEnrollBegin
	HandleTOTPEnrollConfirm        = selfserviceaccount.HandleTOTPEnrollConfirm
	HandleMyIdentities             = selfserviceaccount.HandleMyIdentities
	HandleUnlinkMyIdentity         = selfserviceaccount.HandleUnlinkMyIdentity
	HandleGenerateRecoveryCodes    = selfserviceaccount.HandleGenerateRecoveryCodes
	HandleGetRecoveryCodesCount    = selfserviceaccount.HandleGetRecoveryCodesCount
)
