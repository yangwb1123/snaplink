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
