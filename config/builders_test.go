package config

import (
	"context"
	"testing"

	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/permissions"
)

// ---------- BuildPermissionProvider ----------

func TestBuildPermissionProvider_DisabledReturnsNil(t *testing.T) {
	c := &Config{}
	c.Permissions.Enabled = false
	if got := c.BuildPermissionProvider(); got != nil {
		t.Errorf("BuildPermissionProvider on disabled config = %v, want nil", got)
	}
}

func TestBuildPermissionProvider_AppsRolesMenusUserRoles(t *testing.T) {
	c := &Config{}
	c.Permissions.Enabled = true
	c.Permissions.Apps = []AppPermissionsConfig{
		{
			ClientID: "web-app",
			Roles: []permissions.Role{
				{Code: "admin", Name: "Admin", Permissions: []string{"user:*"}},
				{Code: "viewer", Name: "Viewer", Permissions: []string{"user:read"}},
			},
			Menus: permissions.MenuTree{
				{ID: "m-users", Name: "Users", Permission: "user:read"},
			},
		},
	}
	c.Permissions.UserRoles = []UserRoleAssignment{
		{UserID: "alice", ClientID: "web-app", Roles: []string{"admin"}},
		{UserID: "bob", ClientID: "web-app", Roles: []string{"viewer"}},
	}

	prov := c.BuildPermissionProvider()
	if prov == nil {
		t.Fatal("BuildPermissionProvider returned nil with Enabled=true")
	}

	// Roles registered.
	roles, _ := prov.ListAllRoles(context.Background(), "web-app")
	if len(roles) != 2 {
		t.Errorf("ListAllRoles len = %d, want 2", len(roles))
	}

	// Menus seeded.
	menus, _ := prov.GetMenus(context.Background(), "web-app")
	if len(menus) != 1 || menus[0].ID != "m-users" {
		t.Errorf("Menus = %v", menus)
	}

	// User assignments applied.
	aliceRoles, _ := prov.Roles(context.Background(), "alice", "web-app")
	if len(aliceRoles) != 1 || aliceRoles[0].Code != "admin" {
		t.Errorf("alice roles = %v", aliceRoles)
	}
	bobRoles, _ := prov.Roles(context.Background(), "bob", "web-app")
	if len(bobRoles) != 1 || bobRoles[0].Code != "viewer" {
		t.Errorf("bob roles = %v", bobRoles)
	}
}

func TestBuildPermissionProvider_EmptyAppsStillReturnsProvider(t *testing.T) {
	// Enabled=true with no apps must still return a usable empty Provider.
	c := &Config{}
	c.Permissions.Enabled = true
	prov := c.BuildPermissionProvider()
	if prov == nil {
		t.Fatal("expected non-nil provider")
	}
	// Reading on it should be safe.
	roles, err := prov.ListAllRoles(context.Background(), "x")
	if err != nil {
		t.Errorf("ListAllRoles: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("got %d roles, want 0", len(roles))
	}
}

// ---------- BuildNetworkStore ----------

func TestBuildNetworkStore_DisabledReturnsNil(t *testing.T) {
	c := &Config{}
	c.Network.Enabled = false
	store, err := c.BuildNetworkStore()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store != nil {
		t.Errorf("store = %v, want nil for disabled", store)
	}
}

func TestBuildNetworkStore_MemoryBackend(t *testing.T) {
	c := &Config{}
	c.Network.Enabled = true
	c.Network.Store = "memory"
	c.Network.Policies = []NetworkPolicySeed{
		{
			Name:     "intranet",
			CIDRs:    []string{"10.0.0.0/8"},
			Priority: 100,
			Metadata: map[string]string{"site": "hq"},
		},
		{
			Name:     "public",
			CIDRs:    []string{"0.0.0.0/0"},
			Priority: 1,
		},
	}
	store, err := c.BuildNetworkStore()
	if err != nil {
		t.Fatalf("BuildNetworkStore: %v", err)
	}
	defer store.Close()

	policies, _ := store.List(context.Background())
	if len(policies) != 2 {
		t.Errorf("got %d policies, want 2", len(policies))
	}
}

func TestBuildNetworkStore_DefaultBackendIsMemory(t *testing.T) {
	c := &Config{}
	c.Network.Enabled = true
	// Store="" should default to memory, not error.
	store, err := c.BuildNetworkStore()
	if err != nil {
		t.Fatalf("default backend err: %v", err)
	}
	if store == nil {
		t.Fatal("default backend returned nil store")
	}
	defer store.Close()
}

func TestBuildNetworkStore_UnknownBackend(t *testing.T) {
	c := &Config{}
	c.Network.Enabled = true
	c.Network.Store = "mythical"
	if _, err := c.BuildNetworkStore(); err == nil {
		t.Error("expected error for unknown backend")
	}
}

func TestBuildNetworkStore_EtcdNeedsCmdConstruction(t *testing.T) {
	// The lazy-import path returns a documented error directing
	// operators to cmd/sso-server for etcd construction.
	c := &Config{}
	c.Network.Enabled = true
	c.Network.Store = "etcd"
	_, err := c.BuildNetworkStore()
	if err == nil {
		t.Error("expected etcd backend to require cmd/sso-server wiring")
	}
}

func TestBuildNetworkStore_SeedFailureClosesStore(t *testing.T) {
	// A seed with an empty Name causes Apply to fail (the only
	// validation the memory backend performs). The builder must
	// Close the partially-populated store and surface the error.
	c := &Config{}
	c.Network.Enabled = true
	c.Network.Store = "memory"
	c.Network.Policies = []NetworkPolicySeed{
		{Name: "", CIDRs: []string{"10.0.0.0/8"}}, // empty Name → Apply rejects
	}
	if _, err := c.BuildNetworkStore(); err == nil {
		t.Error("expected error on empty policy Name")
	}
}

// ---------- applyCodeDefaults ----------

func TestApplyCodeDefaults_ZeroValuesGetDefaults(t *testing.T) {
	c := &CodeAuthConfig{}
	applyCodeDefaults(c, 7*authenticators.DefaultPhoneCodeTTL)
	if c.CodeLength != authenticators.DefaultCodeLength {
		t.Errorf("CodeLength = %d", c.CodeLength)
	}
	if c.CodeTTL != 7*authenticators.DefaultPhoneCodeTTL {
		t.Errorf("CodeTTL = %v", c.CodeTTL)
	}
}

func TestApplyCodeDefaults_NonZeroValuesPreserved(t *testing.T) {
	c := &CodeAuthConfig{CodeLength: 12, CodeTTL: authenticators.DefaultPhoneCodeTTL * 3}
	applyCodeDefaults(c, authenticators.DefaultPhoneCodeTTL)
	if c.CodeLength != 12 {
		t.Errorf("CodeLength = %d, want 12 (preserved)", c.CodeLength)
	}
	if c.CodeTTL != authenticators.DefaultPhoneCodeTTL*3 {
		t.Errorf("CodeTTL changed: %v", c.CodeTTL)
	}
}

// ---------- Loader Sources accessor ----------

func TestLoader_SourcesReturnsConfiguredChain(t *testing.T) {
	a := NewFileSource("/nonexistent-a")
	b := NewFileSource("/nonexistent-b")
	l := NewLoader(a, b)
	got := l.Sources()
	if len(got) != 2 {
		t.Errorf("Sources len = %d, want 2", len(got))
	}
}
