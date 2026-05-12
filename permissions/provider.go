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
}
