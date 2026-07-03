package admin

import (
	"context"

	"github.com/snaplink/sso/domains/conditionalaccess"
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
	// ConditionalAccessStore backs the read-only zero-trust CAP governance
	// view; may be nil when WithConditionalAccess isn't wired.
	ConditionalAccessStore() conditionalaccess.Store
	TenantUserStore() core.TenantUserStore
	InvitationStore() core.InvitationStore
	InvitationSender() spi.InvitationSender
	ConsentStore() core.ConsentStore
	MFAEnrollmentStore() core.MFAEnrollmentStore
	PasswordCredentialStore() core.PasswordCredentialStore
	UserProvider() core.UserProvider
	AccountLockout() security.AccountLockout
	DeviceSecretStore() core.DeviceSecretStore
	PasswordResetStore() core.PasswordResetStore
	EmailChangeStore() core.EmailChangeStore
	Auditor() *audit.Recorder
	Logger() spi.Logger
	// SessionMgr backs break-glass impersonation session minting +
	// revocation cascade (readonly-scope grants never call it — no session
	// is minted, so a nil SessionManager only disables impersonate/escalate).
	SessionMgr() core.SessionManager
	// BreakGlassStore persists break-glass (emergency support) admin
	// sessions. Nil ⇒ the break-glass routes are NOT mounted.
	BreakGlassStore() core.BreakGlassStore
	// MintImpersonationToken issues the marked, TTL-bounded bearer that
	// authenticates as a.TargetUserID through the SAME token-issuance path a
	// normal user token uses — so the target user's own permission/scope
	// boundary applies and NOTHING is widened (NON-BYPASS). It refuses any
	// grant that is not impersonate/escalate scope and clamps the lifetime to
	// a.ExpiresAt. Returns an error (never a partial token) when no token
	// issuer is resolvable or issuance fails.
	MintImpersonationToken(ctx context.Context, a core.AdminSession) (core.ImpersonationCredential, error)
	// RevokeToken denies a bearer across every registered issuer (publishing on
	// the cluster bus like /token/revoke). The break-glass cascade uses it to
	// kill impersonation credentials the instant a grant is revoked/expired, and
	// to clean up a token whose atomic attach lost a race. Best-effort.
	RevokeToken(ctx context.Context, token string)
	// InvalidateConnectionCache publishes a KindConnectionChange event to the
	// cluster bus so peer replicas evict any cached connection config for connID.
	// Called after every connection upsert and delete. Fire-and-forget: a bus
	// failure is logged but does not roll back the already-committed store write.
	InvalidateConnectionCache(connID string)
}
