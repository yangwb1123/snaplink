package admin

import (
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// Deps is what the admin management-plane handlers need. *sso.Server satisfies
// it via accessor methods. Every admin operation is gated UPSTREAM by
// AdminMiddleware (admin:read / admin:write on the /api/v1/admin/ prefix); these
// handlers run only after that gate, so they assume admin authorization.
type Deps interface {
	ConnectionStore() connections.Store
	TenantUserStore() core.TenantUserStore
	InvitationStore() core.InvitationStore
	InvitationSender() spi.InvitationSender
	ConsentStore() core.ConsentStore
	MFAEnrollmentStore() core.MFAEnrollmentStore
	RecoveryCodeStore() core.RecoveryCodeStore
	PasswordCredentialStore() core.PasswordCredentialStore
	UserProvider() core.UserProvider
	AccountLockout() security.AccountLockout
	DeviceSecretStore() core.DeviceSecretStore
	PasswordResetStore() core.PasswordResetStore
	EmailChangeStore() core.EmailChangeStore
	Auditor() *audit.Recorder
	Logger() spi.Logger
	// InvalidateConnectionCache publishes a KindConnectionChange event to the
	// cluster bus so peer replicas evict any cached connection config for connID.
	// Called after every connection upsert and delete. Fire-and-forget: a bus
	// failure is logged but does not roll back the already-committed store write.
	InvalidateConnectionCache(connID string)
}
