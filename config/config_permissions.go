package config

import "github.com/snaplink/sso/permissions"

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
