package permissions

import (
	"context"
	"errors"
)

// ErrUserNotFound is returned when no role mapping exists for the user.
var ErrUserNotFound = errors.New("permissions: user has no permissions for client")

// Provider resolves a user's effective permissions, roles, and menu tree for
// a given app (clientID). All three queries take clientID so multi-app
// deployments can present the same user with different surfaces.
//
// Implementations should be cheap to call: the HTTP layer hits Provider on
// every /permissions/me / /menus/me / /roles/me request, and optionally on
// every login (when WithEmbedPermissionsInLogin is set). Cache inside the
// implementation if your source is slow.
type Provider interface {
	Permissions(ctx context.Context, userID, clientID string) ([]Permission, error)
	Roles(ctx context.Context, userID, clientID string) ([]Role, error)
	Menus(ctx context.Context, userID, clientID string) (MenuTree, error)

	// --- admin mutations ---

	// AddRole registers a new role under clientID. Returns ErrRoleExists if
	// the code is taken. UpdateRole replaces an existing role's fields.
	AddRole(ctx context.Context, clientID string, role Role) error
	UpdateRole(ctx context.Context, clientID string, role Role) error
	RemoveRole(ctx context.Context, clientID, roleCode string) error

	AssignRoles(ctx context.Context, userID, clientID string, roles []string) error
	UnassignRoles(ctx context.Context, userID, clientID string, roles []string) error

	SetMenus(ctx context.Context, clientID string, menus MenuTree) error

	// ListAllRoles returns every role defined under clientID, regardless of
	// who's assigned to it.
	ListAllRoles(ctx context.Context, clientID string) ([]Role, error)

	// ListAssignments returns every (userID, []roleCodes) tuple under
	// clientID. Empty when nobody is assigned.
	ListAssignments(ctx context.Context, clientID string) ([]Assignment, error)
}

// Assignment is one (user, roles[]) pairing returned by ListAssignments.
type Assignment struct {
	UserID string   `json:"user_id"`
	Roles  []string `json:"roles"`
}

// MenuLister is an optional extension to Provider for callers that need
// the raw menu tree per client without the user-permission filtering
// applied by Provider.Menus. Snapshotters and admin export tools use it
// to round-trip menu config across nodes; runtime callers should keep
// using Provider.Menus.
//
// Implementations are encouraged to satisfy this interface — the in-memory
// MemoryProvider does — but it is not required of every Provider.
type MenuLister interface {
	GetMenus(ctx context.Context, clientID string) (MenuTree, error)
}

// GroupMembershipWriter is an optional extension to Provider for callers
// that need to add/remove a SINGLE role from a user's assignment list
// without clobbering the user's other roles. The base Provider only
// offers AssignRoles (which SETS the whole list, so it can't grant one
// role without first reading the rest) and UnassignRoles (which removes
// specific codes); a delta over a plain AssignRoles is a read-modify-write
// race when two callers touch the same user concurrently.
//
// SCIM Group membership (RFC 7644 §3.5.2 PATCH add/remove member) maps
// onto exactly these two operations: a SCIM group IS a role, its members
// are the users assigned that role, and an IdP pushes membership deltas
// one member at a time. Both methods are idempotent — AddRoleToUser is a
// no-op when the role is already held, RemoveRoleFromUser a no-op when it
// isn't — so a connector that re-sends a delta doesn't corrupt state.
//
// Implementations are encouraged to satisfy this interface atomically (the
// in-memory MemoryProvider and the SQLite peer both do) — it is not
// required of every Provider. The SCIM Group handler falls back to a
// Roles + AssignRoles read-modify-write when a Provider doesn't implement
// it, so Groups work against any Provider (just without the atomicity
// guarantee on concurrent single-member writes).
type GroupMembershipWriter interface {
	// AddRoleToUser grants roleCode to userID under clientID, preserving
	// any roles already assigned. Idempotent: a no-op when already held.
	AddRoleToUser(ctx context.Context, userID, clientID, roleCode string) error
	// RemoveRoleFromUser revokes roleCode from userID under clientID,
	// leaving the user's other roles intact. Idempotent: a no-op when the
	// role isn't currently assigned.
	RemoveRoleFromUser(ctx context.Context, userID, clientID, roleCode string) error
}

// Sentinel errors returned by Provider implementations. Admin RPCs translate
// these into gRPC status codes.
var (
	ErrRoleExists   = errors.New("permissions: role already exists")
	ErrRoleNotFound = errors.New("permissions: role not found")
)
