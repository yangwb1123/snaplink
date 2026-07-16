package config

import (
	"context"
	"fmt"

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
// static config. Returns (nil, nil) when permissions are disabled.
//
// A duplicate role code within one app's roles list (AddRole's ErrRoleExists)
// or a user_roles entry that violates a declared SSoD set (AssignRoles'
// *ConflictError) aborts the build with an error identifying the offending
// app/user, instead of silently dropping the role/assignment — a copy-paste
// duplicate in the YAML previously vanished with zero boot-time warning, only
// surfacing as a missing permission in production.
func (c *Config) BuildPermissionProvider() (*permissions.MemoryProvider, error) {
	if !c.Permissions.Enabled {
		return nil, nil
	}
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	for _, app := range c.Permissions.Apps {
		for _, role := range app.Roles {
			if err := p.AddRole(ctx, app.ClientID, role); err != nil {
				return nil, fmt.Errorf("permissions.apps[client_id=%q].roles[code=%q]: %w", app.ClientID, role.Code, err)
			}
		}
		if app.Menus != nil {
			if err := p.SetMenus(ctx, app.ClientID, app.Menus); err != nil {
				return nil, fmt.Errorf("permissions.apps[client_id=%q].menus: %w", app.ClientID, err)
			}
		}
	}
	for _, a := range c.Permissions.UserRoles {
		if err := p.AssignRoles(ctx, a.UserID, a.ClientID, a.Roles); err != nil {
			return nil, fmt.Errorf("permissions.user_roles[user_id=%q, client_id=%q]: %w", a.UserID, a.ClientID, err)
		}
	}
	return p, nil
}
