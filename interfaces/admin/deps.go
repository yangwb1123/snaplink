package admin

import (
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/permissions"
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
	// ClientStore / SessionManager / Permissions back the tenant-export
	// handler's compliance.TenantExporter (see tenant_export.go). Each is
	// independently nil-tolerant downstream — the exporter skips a section
	// rather than erroring when its store isn't wired.
	ClientStore() core.ClientStore
	SessionManager() core.SessionManager
	Permissions() permissions.Provider
	// DomainResolver is the DNS-TXT resolver the connection domain-verify
	// handler uses to read a challenge record. Injectable (first-class DI) so
	// tests run network-free with a fake and operators can supply a
	// DNS-over-HTTPS resolver; the production default is stdlib-backed.
	DomainResolver() connections.DNSResolver
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
