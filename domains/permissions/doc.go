// Package permissions models RBAC-style authorization data: permission codes,
// roles that bundle them, and a menu tree for UI rendering. The Provider
// interface is the integration point — implementations may pull from a static
// config (MemoryProvider), a database, or an external policy engine.
//
// The package has zero dependency on the sso package. The sso server reads
// from a Provider via WithPermissionProvider and exposes /permissions/me,
// /menus/me, /roles/me — but other layers (a gateway, a CLI, a custom HTTP
// handler) can use the same Provider directly.
package permissions
