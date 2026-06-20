package config

import (
	"context"

	"github.com/snaplink/sso/domains/permissions"
)

type PermissionsConfig struct {
	Enabled      bool                    `yaml:"enabled"`
	Backend      string                  `yaml:"backend"` // memory | sqlite
	SQLite       PermissionsSQLiteConfig `yaml:"sqlite"`
	EmbedInLogin bool                    `yaml:"embed_in_login"`
	Apps         []AppPermissionsConfig  `yaml:"apps"`
	UserRoles    []UserRoleAssignment    `yaml:"user_roles"`
}

// PermissionsSQLiteConfig is the SQLite backend's DSN.
type PermissionsSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// AppPermissionsConfig declares the roles and menu tree for one APP. Roles
// listed here are referenced by UserRoleAssignment.Roles for assignment.
type AppPermissionsConfig struct {
	ClientID string               `yaml:"client_id"`
	Roles    []permissions.Role   `yaml:"roles"`
	Menus    permissions.MenuTree `yaml:"menus"`
}

// UserRoleAssignment binds a user to a set of role codes within a given APP.
type UserRoleAssignment struct {
	UserID   string   `yaml:"user_id"`
	ClientID string   `yaml:"client_id"`
	Roles    []string `yaml:"roles"`
}

// BuildPermissionProvider materializes a permissions.MemoryProvider from the
// static config. Returns nil when permissions are disabled.
func (c *Config) BuildPermissionProvider() *permissions.MemoryProvider {
	if !c.Permissions.Enabled {
		return nil
	}
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	for _, app := range c.Permissions.Apps {
		for _, role := range app.Roles {
			_ = p.AddRole(ctx, app.ClientID, role)
		}
		if app.Menus != nil {
			_ = p.SetMenus(ctx, app.ClientID, app.Menus)
		}
	}
	for _, a := range c.Permissions.UserRoles {
		_ = p.AssignRoles(ctx, a.UserID, a.ClientID, a.Roles)
	}
	return p
}
