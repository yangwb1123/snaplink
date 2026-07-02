package admin

import (
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/metrics"
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
	// DomainResolver is the DNS-TXT resolver the connection domain-verify
	// handler uses to read a challenge record. Injectable (first-class DI) so
	// tests run network-free with a fake and operators can supply a
	// DNS-over-HTTPS resolver; the production default is stdlib-backed.
	DomainResolver() connections.DNSResolver
	// ConnectionProber performs the admin-triggered reachability check
	// (POST .../connections/:id/probe) against a connection's configured
	// upstream. Injectable (first-class DI) so tests run network-free with a
	// fake; the production default issues the real OIDC discovery / SAML
	// metadata fetch.
	ConnectionProber() connections.Prober
	// Metrics returns the wired Prometheus collectors, or nil when
	// sso.WithMetrics was never configured — every call site nil-checks.
	Metrics() *metrics.Metrics
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
