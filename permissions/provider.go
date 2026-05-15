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

// Sentinel errors returned by Provider implementations. Admin RPCs translate
// these into gRPC status codes.
var (
	ErrRoleExists   = errors.New("permissions: role already exists")
	ErrRoleNotFound = errors.New("permissions: role not found")
)
