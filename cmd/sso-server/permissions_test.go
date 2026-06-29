package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/permissions"
)

func TestBuildPermissionsProvider_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	p, err := serverbuildplatform.BuildPermissionsProvider(cfg, quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Fatalf("disabled config should return nil provider; got %v", p)
	}
}

func TestBuildPermissionsProvider_MemoryDefault(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Permissions = config.PermissionsConfig{Enabled: true}
	p, err := serverbuildplatform.BuildPermissionsProvider(cfg, quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("serverbuildplatform.BuildPermissionsProvider: %v", err)
	}
	if p == nil {
		t.Fatal("memory backend should produce a provider")
	}
	// The returned provider should be usable for an admin AddRole.
	if err := p.AddRole(context.Background(), "web", permissions.Role{Code: "admin", Permissions: []string{"all"}}); err != nil {
		t.Errorf("AddRole through wired provider: %v", err)
	}
}

func TestBuildPermissionsProvider_SQLiteRequiresDSN(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Permissions = config.PermissionsConfig{
		Enabled: true,
		Backend: "sqlite",
	}
	_, err := serverbuildplatform.BuildPermissionsProvider(cfg, quietLogger(), nil, "")
	if err == nil {
		t.Fatal("want error when sqlite backend missing DSN")
	}
}

func TestBuildPermissionsProvider_SQLiteSeedsAppsAndAssignments(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "permissions.db") + "?_journal=WAL"
	cfg := &config.Config{}
	cfg.Permissions = config.PermissionsConfig{
		Enabled: true,
		Backend: "sqlite",
		SQLite:  config.PermissionsSQLiteConfig{DSN: dsn},
		Apps: []config.AppPermissionsConfig{
			{
				ClientID: "web",
				Roles: []permissions.Role{
					{Code: "admin", Permissions: []string{"user:*", "order:*"}},
					{Code: "viewer", Permissions: []string{"user:read"}},
				},
			},
		},
		UserRoles: []config.UserRoleAssignment{
			{UserID: "alice", ClientID: "web", Roles: []string{"admin"}},
			{UserID: "bob", ClientID: "web", Roles: []string{"viewer"}},
		},
	}
	p, err := serverbuildplatform.BuildPermissionsProvider(cfg, quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("serverbuildplatform.BuildPermissionsProvider: %v", err)
	}
	if p == nil {
		t.Fatal("provider nil")
	}
	ctx := context.Background()

	// Roles were AddRole'd.
	all, _ := p.ListAllRoles(ctx, "web")
	if len(all) != 2 {
		t.Fatalf("ListAllRoles = %d, want 2", len(all))
	}
	// Assignments were AssignRoles'd.
	aliceRoles, err := p.Roles(ctx, "alice", "web")
	if err != nil {
		t.Fatalf("alice Roles: %v", err)
	}
	if len(aliceRoles) != 1 || aliceRoles[0].Code != "admin" {
		t.Errorf("alice roles = %v, want [admin]", aliceRoles)
	}
}

func TestBuildPermissionsProvider_SQLiteSeedIsIdempotent(t *testing.T) {
	t.Parallel()
	// Operators re-running cmd against an already-seeded DSN should
	// see no errors + the YAML state re-applied (idempotent reseed).
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "permissions.db") + "?_journal=WAL"
	mkCfg := func(adminPerms []string) *config.Config {
		cfg := &config.Config{}
		cfg.Permissions = config.PermissionsConfig{
			Enabled: true,
			Backend: "sqlite",
			SQLite:  config.PermissionsSQLiteConfig{DSN: dsn},
			Apps: []config.AppPermissionsConfig{
				{
					ClientID: "web",
					Roles: []permissions.Role{
						{Code: "admin", Permissions: adminPerms},
					},
				},
			},
		}
		return cfg
	}
	// First seed.
	p1, err := serverbuildplatform.BuildPermissionsProvider(mkCfg([]string{"v1:a"}), quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("first seed: %v", err)
	}
	_ = p1.(interface{ Close() error }).Close()

	// Second seed with updated permissions list — operator changed
	// YAML between restarts; reseed should UpdateRole.
	p2, err := serverbuildplatform.BuildPermissionsProvider(mkCfg([]string{"v2:a", "v2:b"}), quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	defer func() { _ = p2.(interface{ Close() error }).Close() }()
	roles, _ := p2.ListAllRoles(context.Background(), "web")
	if len(roles) != 1 {
		t.Fatalf("re-seed should not duplicate role rows; got %v", roles)
	}
	if len(roles[0].Permissions) != 2 || roles[0].Permissions[0] != "v2:a" {
		t.Errorf("re-seed didn't update permissions; got %v, want [v2:a v2:b]", roles[0].Permissions)
	}
}

func TestBuildPermissionsProvider_UnknownBackendRejected(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Permissions = config.PermissionsConfig{
		Enabled: true,
		Backend: "redis",
	}
	_, err := serverbuildplatform.BuildPermissionsProvider(cfg, quietLogger(), nil, "")
	if err == nil {
		t.Fatal("want error on unknown backend")
	}
}

// Sanity: the wired SQLite provider satisfies the same ErrUserNotFound
// sentinel the memory peer does — operator audit paths branching on
// this don't have to special-case backends.
func TestBuildPermissionsProvider_SQLiteRolesUnknownUser(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "permissions.db") + "?_journal=WAL"
	cfg := &config.Config{}
	cfg.Permissions = config.PermissionsConfig{
		Enabled: true,
		Backend: "sqlite",
		SQLite:  config.PermissionsSQLiteConfig{DSN: dsn},
	}
	p, err := serverbuildplatform.BuildPermissionsProvider(cfg, quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("serverbuildplatform.BuildPermissionsProvider: %v", err)
	}
	defer func() { _ = p.(interface{ Close() error }).Close() }()

	_, err = p.Roles(context.Background(), "ghost", "web")
	if !errors.Is(err, permissions.ErrUserNotFound) {
		t.Fatalf("got %v, want ErrUserNotFound", err)
	}
}
