package config

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/permissions"
)

// ---------- BuildPermissionProvider ----------

func TestBuildPermissionProvider_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	c := &Config{}
	c.Permissions.Enabled = false
	got, err := c.BuildPermissionProvider()
	if err != nil {
		t.Fatalf("BuildPermissionProvider on disabled config returned error: %v", err)
	}
	if got != nil {
		t.Errorf("BuildPermissionProvider on disabled config = %v, want nil", got)
	}
}

func TestBuildPermissionProvider_AppsRolesMenusUserRoles(t *testing.T) {
	t.Parallel()
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

	prov, err := c.BuildPermissionProvider()
	if err != nil {
		t.Fatalf("BuildPermissionProvider: %v", err)
	}
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
	t.Parallel()
	// Enabled=true with no apps must still return a usable empty Provider.
	c := &Config{}
	c.Permissions.Enabled = true
	prov, err := c.BuildPermissionProvider()
	if err != nil {
		t.Fatalf("BuildPermissionProvider: %v", err)
	}
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

// TestBuildPermissionProvider_DuplicateRoleCodeReturnsError proves a
// copy-paste duplicate role code within one app's roles list aborts the
// build with an error identifying the offending app/role, instead of the
// pre-fix behavior of silently dropping the duplicate (AddRole's
// ErrRoleExists was discarded) with no boot-time warning.
func TestBuildPermissionProvider_DuplicateRoleCodeReturnsError(t *testing.T) {
	t.Parallel()
	c := &Config{}
	c.Permissions.Enabled = true
	c.Permissions.Apps = []AppPermissionsConfig{
		{
			ClientID: "web-app",
			Roles: []permissions.Role{
				{Code: "admin", Name: "Admin", Permissions: []string{"user:*"}},
				{Code: "admin", Name: "Admin Duplicate", Permissions: []string{"user:read"}},
			},
		},
	}
	prov, err := c.BuildPermissionProvider()
	if err == nil {
		t.Fatal("BuildPermissionProvider with a duplicate role code = nil error, want an error naming the conflict")
	}
	if !errors.Is(err, permissions.ErrRoleExists) {
		t.Errorf("error = %v, want it to wrap permissions.ErrRoleExists", err)
	}
	if prov != nil {
		t.Errorf("provider = %v, want nil on error", prov)
	}
}

// ---------- BuildNetworkStore ----------

func TestBuildNetworkStore_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	defer func() { _ = store.Close() }()

	policies, _ := store.List(context.Background())
	if len(policies) != 2 {
		t.Errorf("got %d policies, want 2", len(policies))
	}
}

func TestBuildNetworkStore_DefaultBackendIsMemory(t *testing.T) {
	t.Parallel()
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
	defer func() { _ = store.Close() }()
}

func TestBuildNetworkStore_UnknownBackend(t *testing.T) {
	t.Parallel()
	c := &Config{}
	c.Network.Enabled = true
	c.Network.Store = "mythical"
	if _, err := c.BuildNetworkStore(); err == nil {
		t.Error("expected error for unknown backend")
	}
}

func TestBuildNetworkStore_EtcdNeedsCmdConstruction(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	c := &CodeAuthConfig{CodeLength: 12, CodeTTL: authenticators.DefaultPhoneCodeTTL * 3}
	applyCodeDefaults(c, authenticators.DefaultPhoneCodeTTL)
	if c.CodeLength != 12 {
		t.Errorf("CodeLength = %d, want 12 (preserved)", c.CodeLength)
	}
	if c.CodeTTL != authenticators.DefaultPhoneCodeTTL*3 {
		t.Errorf("CodeTTL changed: %v", c.CodeTTL)
	}
}

func TestCodeSendQuotaDefaultsAndValidation(t *testing.T) {
	t.Parallel()
	c := &Config{}
	c.applyDefaults()
	quota := c.Authenticators.CodeSendQuota
	if quota.IdentityLimit != authenticators.DefaultCodeIdentitySendLimit ||
		quota.TenantLimit != authenticators.DefaultCodeTenantSendLimit ||
		quota.Window != authenticators.DefaultCodeSendQuotaWindow {
		t.Fatalf("quota defaults = %+v", quota)
	}
	c.Authenticators.CodeSendQuota.IdentityLimit = -2
	if err := c.validateCodeSendQuota(); err == nil {
		t.Fatal("invalid negative quota should fail")
	}
}

func TestCodeDeliveryValidation(t *testing.T) {
	t.Parallel()
	if err := (CodeDeliveryConfig{Async: true, Workers: 2, Attempts: 3}).validate(); err != nil {
		t.Fatalf("valid delivery config: %v", err)
	}
	if err := (CodeDeliveryConfig{Async: true, QueueSize: -1}).validate(); err == nil {
		t.Fatal("negative delivery config should fail")
	}
	if err := (CodeDeliveryConfig{Async: true, Attempts: authenticators.MaxCodeDeliveryAttempts + 1}).validate(); err == nil {
		t.Fatal("excessive delivery config should fail")
	}
}

func TestBCLFailureQueueDefaultsAndValidation(t *testing.T) {
	t.Parallel()
	c := &Config{BackchannelLogout: BackchannelLogoutConfig{
		Enabled: true, FailureQueue: BCLFailureQueueConfig{Backend: "redis"},
	}}
	c.applyDefaults()
	queue := c.BackchannelLogout.FailureQueue
	if queue.RetryInterval != 30*time.Second || queue.BatchSize != 50 || queue.LeaseDuration != 30*time.Second {
		t.Fatalf("failure queue defaults = %+v", queue)
	}
	if err := c.validateBCLFailureQueue(); err != nil {
		t.Fatalf("valid failure queue: %v", err)
	}
	c.BackchannelLogout.Enabled = false
	if err := c.validateBCLFailureQueue(); err == nil {
		t.Fatal("failure queue without BCL should fail")
	}
}

// ---------- Loader Sources accessor ----------

func TestLoader_SourcesReturnsConfiguredChain(t *testing.T) {
	t.Parallel()
	a := NewFileSource("/nonexistent-a")
	b := NewFileSource("/nonexistent-b")
	l := NewLoader(a, b)
	got := l.Sources()
	if len(got) != 2 {
		t.Errorf("Sources len = %d, want 2", len(got))
	}
}
