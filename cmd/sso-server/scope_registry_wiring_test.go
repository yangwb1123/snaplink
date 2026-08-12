package main

// Boot-level wiring tests for the scope registry (B4-2): the shipped binary
// builds the Memory registry from config when oauth.scope_registry.enabled is
// true and passes nil (no WithScopeRegistry option) otherwise — the verdict is
// a pure function of the config snapshot, so two replicas with the same
// snapshot answer identically (FM-1/FM-2/FM-8).

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/scopecontract"
)

func TestBuildApp_ScopeRegistryDisabledByDefault(t *testing.T) {
	t.Parallel()
	a, err := buildApp(&config.Config{}, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)
	if reg := a.server.ScopeRegistry(); reg != nil {
		t.Fatal("default config must leave the registry unwired (nil) — byte-identical baseline")
	}
}

func TestBuildApp_ScopeRegistryEnabledBuildsMatrix(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.OAuth.ScopeRegistry.Enabled = true
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)
	reg := a.server.ScopeRegistry()
	if reg == nil {
		t.Fatal("enabled config must wire a registry")
	}
	for _, sc := range scopecontract.Matrix() {
		if !reg.Registered(sc) {
			t.Errorf("matrix scope %q not registered", sc)
		}
	}
	// Pre-seeded protocol scopes (FM-4) + extra-absence.
	for _, sc := range []string{"openid", "device_sso", "profile", "email", "address", "phone", "offline_access"} {
		if !reg.Registered(sc) {
			t.Errorf("protocol scope %q not registered", sc)
		}
	}
	if reg.Registered("anything") {
		t.Error("unregistered scope reported registered")
	}
}

func TestBuildApp_ScopeRegistryExtraScopes(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.OAuth.ScopeRegistry.Enabled = true
	cfg.OAuth.ScopeRegistry.ExtraScopes = []string{"tenant:quota:write", "relay:*"}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)
	reg := a.server.ScopeRegistry()
	if !reg.Registered("tenant:quota:write") {
		t.Error("extra exact scope not registered")
	}
	if !reg.Registered("relay:event:write") {
		t.Error("extra domain:* scope not matched by prefix")
	}
}

// R1/R5 — a provisioned matrix REPLACES the built-in nine-scope table at the
// registry construction site: only provisioned rows (plus pre-seeded protocol
// scopes and extra_scopes) are registered.
func TestBuildApp_ScopeRegistryProvisionedMatrixReplacesBuiltin(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.OAuth.ScopeRegistry.Enabled = true
	cfg.OAuth.ScopeRegistry.Matrix = []string{"custom:scope"}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)
	reg := a.server.ScopeRegistry()
	if !reg.Registered("custom:scope") {
		t.Error("provisioned matrix scope not registered")
	}
	if reg.Registered("admin:read") {
		t.Error("built-in matrix scope still registered after provisioning replaced it")
	}
	// Pre-seeded protocol scopes are unaffected by provisioning.
	if !reg.Registered("openid") {
		t.Error("protocol scope openid not registered")
	}
}
