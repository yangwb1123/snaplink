package core

import (
	"context"
	"errors"
	"time"
)

// TenantRole is a user's standing WITHIN an organization (tenant). It is
// orthogonal to OAuth scopes and to SCIM group membership: SCIM groups model
// client-scoped role membership (who has which app role), whereas a tenant
// membership models who BELONGS to the org at all and at what org-level
// standing. The two are intentionally decoupled — a user can hold app roles
// without org membership and vice versa.
type TenantRole string

const (
	// TenantRoleMember is the baseline standing: belongs to the org, no
	// org-administration rights.
	TenantRoleMember TenantRole = "member"
	// TenantRoleAdmin can administer the org (manage its roster, settings).
	TenantRoleAdmin TenantRole = "admin"
	// TenantRoleGuest is a constrained, typically external collaborator —
	// counts as a member for residency/tenant-scoping but is not a full member.
	TenantRoleGuest TenantRole = "guest"
)

// TenantMembership is the explicit (tenant, user) edge: it records that a user
// is part of an organization and at what org-level role. The pair
// (TenantID, UserID) is the identity of the edge — there is at most one role
// per user per tenant, so Add is an upsert that updates the role rather than
// creating a duplicate.
type TenantMembership struct {
	TenantID  string     `json:"tenant_id"`
	UserID    string     `json:"user_id"`
	Role      TenantRole `json:"role"`
	CreatedAt time.Time  `json:"created_at"`
}

// TenantUserStore persists explicit org membership independently of SCIM groups
// (which are client-scoped role membership, NOT org membership). When nil (not
// wired), B2B org membership is disabled — byte-identical to a build without it.
// memory + sqlite peers ship in defaultimpl + defaultimpl/sqlite.
//
// The store is the single source of truth for "is this user in this org" and is
// what tenant-scoping / residency gates consult. Add upserts on (tenant, user)
// so re-inviting an existing member is a role update, not a duplicate edge.
type TenantUserStore interface {
	// Add upserts the membership keyed by (TenantID, UserID): a first call
	// creates the edge, a subsequent call for the same pair updates the role.
	// This makes invite/role-change idempotent and keeps at most one row per
	// (tenant, user).
	Add(ctx context.Context, m *TenantMembership) error

	// Remove deletes the (tenantID, userID) membership. Idempotent: removing a
	// membership that does not exist returns nil (no oracle on whether the user
	// was ever a member).
	Remove(ctx context.Context, tenantID, userID string) error

	// Get returns the membership for (tenantID, userID) or ErrNoMembership when
	// the user is not part of that tenant.
	Get(ctx context.Context, tenantID, userID string) (*TenantMembership, error)

	// ListByTenant returns the org roster: every membership in tenantID.
	ListByTenant(ctx context.Context, tenantID string) ([]*TenantMembership, error)

	// ListByUser returns every org the user belongs to (a user's tenants).
	ListByUser(ctx context.Context, userID string) ([]*TenantMembership, error)
}

// ErrNoMembership is the sentinel Get returns when (tenant, user) has no
// membership edge. Callers MUST NOT distinguish "no such tenant" from "no such
// user" from "user not in tenant" — all collapse to this single response.
var ErrNoMembership = errors.New("sso: no such tenant membership")

// ---- Admin user CRUD path constants ----

const (
	// PathAdminLocalUsers is the admin LOCAL (password-authenticated) user
	// list + create endpoint. GET = list (paginated, admin:read), POST =
	// create (admin:write). Group-relative; mounted on the /api/v1 router
	// group under mountAdminUserState.
	//
	// Named "local-users" (not "users") because the admin gRPC-gateway's
	// UserAdminService ALSO claims the literal /api/v1/admin/users shape
	// (proto/admin/v1/users.proto — federated/external-identity records:
	// id/external_id/provider/attributes, no password) and
	// cmd/sso-server's outer mux registers the gateway at that exact
	// pattern (see adminGatewayExactPaths in cmd/sso-server/build_http.go).
	// The two are NOT redundant — this endpoint validates username/email/
	// password and writes to a PasswordCredentialStore, a capability the
	// gateway's wire contract cannot express — so it needs its OWN,
	// non-colliding path rather than being shadowed.
	PathAdminLocalUsers = "/admin/local-users"

	// PathAdminLocalUserByID is the per-local-user read/update/delete
	// endpoint. GET = read (admin:read), PUT = update (admin:write),
	// DELETE = delete (admin:write). Group-relative. See PathAdminLocalUsers
	// for why this is a distinct path from the gateway's /users/{id}.
	PathAdminLocalUserByID = "/admin/local-users/:id"
)

// ---- UserProvider OPTIONAL extension interfaces ----

// UserByUsernameProvider is an OPTIONAL extension a UserProvider MAY implement
// to support efficient username-based user lookup. Callers type-assert before
// using; a UserProvider that does not implement it returns nil for the
// assertion, and the caller must fall back to listing + filtering.
//
// GetByUsername returns the user with the EXACT (case-insensitive) match on
// username. Returns ErrNoSuchUser when not found. Implementations MUST treat
// "" as "not found" (not a wildcard or default).
type UserByUsernameProvider interface {
	GetByUsername(ctx context.Context, username string) (*User, error)
}

// UserByEmailProvider is an OPTIONAL extension a UserProvider MAY implement
// to support efficient email-based user lookup. Same contract as
// UserByUsernameProvider: exact (case-insensitive per RFC 5321 §2.4) match
// on email. Returns ErrNoSuchUser when not found.
type UserByEmailProvider interface {
	GetByEmail(ctx context.Context, email string) (*User, error)
}

// UserPaginationProvider is an OPTIONAL extension a UserProvider MAY implement
// to support paginated listing. Existing List() returns all users (the caller
// paginates client-side); backends with large user sets SHOULD implement this
// to enable server-side offset/limit pagination.
//
// ListPaginated returns a slice of users for the given offset and limit, and
// the TOTAL count of users (not just the page) so the caller can compute page
// metadata. offset=0, limit=0 returns an empty slice with the total count.
// Implementations SHOULD clamp limit to a sane maximum (e.g. 100).
type UserPaginationProvider interface {
	ListPaginated(ctx context.Context, offset, limit int) ([]*User, int, error)
}

// UsernameCheckProvider is an OPTIONAL extension a UserProvider MAY implement
// to support efficient username-existence checks. The admin CRUD handler uses
// this for optimistic pre-flight conflict detection.
//
// UsernameExists returns true when a user with the exact username exists.
type UsernameCheckProvider interface {
	UsernameExists(ctx context.Context, username string) (bool, error)
}

// EmailCheckProvider is an OPTIONAL extension a UserProvider MAY implement
// for efficient email-existence checks. Same contract as
// UsernameCheckProvider, with case-insensitive matching per RFC 5321 §2.4.
type EmailCheckProvider interface {
	EmailExists(ctx context.Context, email string) (bool, error)
}

// ---- Tenant resource quotas ----
// Co-located here (not spi.go, which declares most other tenant SPI) purely
// to stay under spi.go's 500-line budget (AGENTS.md §0.1) — thematically
// still tenant SPI, same family as TenantUserStore above.

// ResourceType identifies a quota-bounded resource dimension.
type ResourceType string

const (
	ResourceClients   ResourceType = "clients"
	ResourceUsers     ResourceType = "users"
	ResourceSessions  ResourceType = "sessions"
	ResourceTokenRate ResourceType = "token_rate"
)

// TenantQuota defines the resource limits for a single tenant.
// Zero values mean "unlimited" (backward compatible with deployments
// that don't wire a quota store).
type TenantQuota struct {
	MaxClients  int `json:"max_clients,omitempty"`
	MaxUsers    int `json:"max_users,omitempty"`
	MaxSessions int `json:"max_sessions,omitempty"`
	// MaxTokenRate is the maximum tokens per second this tenant may
	// issue across all clients. 0 = unlimited.
	MaxTokenRate int `json:"max_token_rate,omitempty"`
}

// TenantUsage records a tenant's current resource consumption.
type TenantUsage struct {
	Clients  int `json:"clients"`
	Users    int `json:"users"`
	Sessions int `json:"sessions"`
	// TokenRate is the current 1-minute rolling average of token
	// issuance requests per second.
	TokenRate float64 `json:"token_rate,omitempty"`
}

// TenantQuotaStore persists and evaluates per-tenant resource quotas.
// When nil (not wired), every Create/Register/Login operation proceeds
// without quota checks — byte-identical to a pre-quota build.
type TenantQuotaStore interface {
	// GetQuota returns the configured quota for tenantID.
	// Returns default (unlimited) quota when none is set.
	GetQuota(ctx context.Context, tenantID string) (*TenantQuota, error)

	// GetUsage returns the current resource consumption for tenantID.
	GetUsage(ctx context.Context, tenantID string) (*TenantUsage, error)

	// IncrementUsage atomically increments the counter for resource.
	// Returns ErrQuotaExceeded when the increment would exceed the limit.
	IncrementUsage(ctx context.Context, tenantID string, resource ResourceType, delta int64) error

	// DecrementUsage atomically decrements the counter for resource, floored
	// at 0 (never negative). Callers use this to compensate a successful
	// IncrementUsage when the resource creation it guarded fails AFTER the
	// charge (e.g. session-store Create errors, DCR client-store Add
	// errors) — without it, a transient downstream failure permanently
	// over-counts usage and can eventually reject legitimate requests under
	// a tenant that is really still under quota.
	DecrementUsage(ctx context.Context, tenantID string, resource ResourceType, delta int64) error

	// SetQuota updates the quota configuration for tenantID.
	SetQuota(ctx context.Context, tenantID string, quota *TenantQuota) error

	// ResetUsage resets usage counters (e.g. after billing period rollover).
	ResetUsage(ctx context.Context, tenantID string) error
}
