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
	case audit.EventAdminRoleAssigned, audit.EventAdminRoleUnassigned:
		return "Application access changed", "An administrator changed roles assigned to your account.", core.NotificationWarning, true
	default:
		return "", "", "", false
	}
}
