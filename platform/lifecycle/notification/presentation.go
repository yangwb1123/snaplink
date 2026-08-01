package notification

import (
	"fmt"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

func auditEventPresentation(event *audit.Event) (string, string, core.NotificationSeverity, bool) {
	switch event.Type {
	case audit.EventPasswordChanged, audit.EventPasswordResetCompleted:
		return "Password changed", "Your account password was changed. Review security activity if this was not you.", core.NotificationWarning, true
	case audit.EventConsentRevoked, audit.EventAdminConsentRevoked:
		return "Application access revoked", fmt.Sprintf("Access was revoked for application %s.", event.ClientID), core.NotificationInfo, true
	case audit.EventRefreshTokenReuse:
		return "Session credential reuse detected", "A reused session credential was detected and its token family was revoked.", core.NotificationCritical, true
	default:
		return adminAuditEventPresentation(event)
	}
}

func adminAuditEventPresentation(event *audit.Event) (string, string, core.NotificationSeverity, bool) {
	switch event.Type {
	case audit.EventAdminMFAFactorRemoved:
		return "Security factor removed by administrator", "An administrator removed one of your multi-factor authentication methods.", core.NotificationWarning, true
	case audit.EventAdminRecoveryCodesReset:
		return "Recovery codes reset by administrator", "Your existing recovery codes were revoked. Generate a new set before you need account recovery.", core.NotificationWarning, true
	case audit.EventAdminPasswordReset:
		return "Password reset by administrator", "An administrator reset your account password. Review security activity if this was unexpected.", core.NotificationWarning, true
	case audit.EventAdminUserEmailChanged:
		return "Email changed by administrator", "An administrator changed the email address associated with your account.", core.NotificationWarning, true
	case audit.EventAdminDeviceSecretsRevoked:
		return "Device credentials revoked", "An administrator revoked device credentials associated with your account.", core.NotificationWarning, true
	case audit.EventAdminRefreshTokensRevoked:
		return "Sessions revoked by administrator", "An administrator revoked your refresh tokens. You may need to sign in again.", core.NotificationWarning, true
	case audit.EventAdminPasswordResetTokensRevoked:
		return "Password reset links revoked", "An administrator revoked your outstanding password reset links.", core.NotificationWarning, true
	case audit.EventAdminEmailChangeTokensRevoked:
		return "Email change requests revoked", "An administrator revoked your outstanding email change requests.", core.NotificationWarning, true
	case audit.EventAdminAccountUnlocked:
		return "Account unlocked by administrator", "An administrator cleared your account lockout. You can try signing in again.", core.NotificationInfo, true
	case audit.EventAdminRoleAssigned, audit.EventAdminRoleUnassigned:
		return "Application access changed", "An administrator changed roles assigned to your account.", core.NotificationWarning, true
	case audit.EventAdminTenantMemberAdded, audit.EventAdminTenantMemberRemoved:
		return "Organization access changed", "An administrator changed your organization membership.", core.NotificationWarning, true
	case audit.EventAdminUserLifecycleChanged:
		return lifecycleChangePresentation(event)
	case audit.EventAdminTempTokenIssued:
		return "Temporary access token issued", "An administrator issued a one-time access token for your account.", core.NotificationWarning, true
	case audit.EventAdminBreakGlassImpersonationStarted:
		return "Emergency access used", "An administrator started an emergency impersonation session for your account.", core.NotificationCritical, true
	default:
		return "", "", "", false
	}
}

func lifecycleChangePresentation(event *audit.Event) (string, string, core.NotificationSeverity, bool) {
	to := event.Metadata["to_state"]
	if to == "active" {
		return "Account access restored", "An administrator changed your account status to active.", core.NotificationInfo, true
	}
	return "Account status changed", fmt.Sprintf("An administrator changed your account status to %s.", to), core.NotificationWarning, true
}
