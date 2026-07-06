package admin

import (
	"context"

	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/userlifecycle"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/admingovernance"
	"github.com/snaplink/sso/protocols/oauth"
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
	// LifecycleStore backs the user-lifecycle state-machine admin endpoints
	// (GET/POST /admin/users/:id/lifecycle); may be nil when WithUserLifecycle
	// isn't wired, in which case those routes are not mounted.
	LifecycleStore() userlifecycle.Store
	AccountLockout() security.AccountLockout
	DeviceSecretStore() core.DeviceSecretStore
	PasswordResetStore() core.PasswordResetStore
	EmailChangeStore() core.EmailChangeStore
	// RefreshTokenStore backs HandleAdminRevokeUserRefreshTokens (the
	// helpdesk "compromised account, log out everywhere" lockout). Type-
	// asserted to oauth.RefreshTokenSubjectIndex — most callers already
	// wire a store with a live subject index for /token/revoke-all, so
	// this reuses the SAME store rather than adding a parallel one.
	RefreshTokenStore() oauth.RefreshTokenStore
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
	// TargetHoldsAdminScope reports whether targetUserID holds an admin scope
	// (admin:read / admin:write, incl. the admin:* wildcard) — the SAME
	// permissions check AdminMiddleware runs on the acting admin. The break-glass
	// impersonation floor uses it to REFUSE minting a bearer for a PRIVILEGED
	// target: impersonating an admin would let support act with that admin's OWN
	// boundary, the one escalation break-glass must never enable. clientID is the
	// acting admin's token audience; implementations SHOULD also consult the
	// empty/global client so a globally-assigned admin is still caught. When no
	// permissions.Provider is wired it returns (false, nil) — the floor is a no-op,
	// preserving break-glass for deployments without RBAC. A provider error is
	// surfaced so the caller can fail CLOSED (refuse) rather than mint blindly.
	TargetHoldsAdminScope(ctx context.Context, targetUserID, clientID string) (bool, error)
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
	// ApprovalStore persists the generic change-approval workflow's pending/
	// decided ChangeRequests (domains/admingovernance). Nil ⇒ the
	// /api/v1/admin/changes routes are NOT mounted.
	ApprovalStore() admingovernance.ApprovalStore
	// ChangeRegistry resolves the Applier (if any) that performs the real
	// mutation a ChangeRequest.ActionType describes, invoked the instant a
	// SECOND admin approves it. May be nil (every change then stays
	// Approved — never auto-applied — for the caller's own follow-through).
	ChangeRegistry() *admingovernance.Registry
	// ApprovalActionTypes is the configured allow-list POST .../changes
	// checks a proposal's action_type against (AdminChangeApprovalConfig.
	// ActionTypes). Empty ⇒ unrestricted — every action_type accepted.
	ApprovalActionTypes() admingovernance.RequiredActionTypes
}
