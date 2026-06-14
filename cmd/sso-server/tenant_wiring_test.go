package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
)

// TestBuildApp_RefreshRotationGrace_BuildsCleanly verifies a configured refresh
// rotation grace window is accepted by buildApp (the option only applies when
// the refresh store is enabled and the window > 0).
func TestBuildApp_RefreshRotationGrace_BuildsCleanly(t *testing.T) {
	cfg := &config.Config{}
	cfg.OAuth.RefreshToken = config.OAuthRefreshTokenConfig{
		OAuthStoreConfig: config.OAuthStoreConfig{
			Enabled:             true,
			TTL:                 time.Hour,
			RotationGraceWindow: 5 * time.Second,
		},
	}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp with refresh rotation grace: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
}

func TestBuildTenantUsageAggregator_DisabledByDefault(t *testing.T) {
	a, err := buildTenantUsageAggregator(config.TenantUsageMeteringConfig{})
	if err != nil {
		t.Fatalf("disabled build: %v", err)
	}
	if a != nil {
		t.Fatalf("expected nil aggregator when backend empty, got %T", a)
	}
}

func TestBuildTenantUsageAggregator_Memory(t *testing.T) {
	a, err := buildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "memory"})
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if a == nil {
		t.Fatal("memory aggregator nil")
	}
}

func TestBuildTenantUsageAggregator_SQLiteNeedsDSN(t *testing.T) {
	if _, err := buildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "sqlite"}); err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildTenantUsageAggregator_SQLiteOpensFile(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db") + "?_journal=WAL"
	a, err := buildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if a == nil {
		t.Fatal("sqlite aggregator nil")
	}
}

func TestBuildTenantUsageAggregator_UnknownBackend(t *testing.T) {
	if _, err := buildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "bogus"}); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

// TestBuildApp_TenantTokenStrategy_RejectsUnregistered verifies an unregistered
// per-tenant token_strategy fails loud at boot (it would break login at runtime).
func TestBuildApp_TenantTokenStrategy_RejectsUnregistered(t *testing.T) {
	cfg := &config.Config{}
	cfg.Tenant.Enabled = true
	cfg.Tenant.Backend = "memory"
	cfg.Tenant.Tenants = []config.TenantSeedConfig{
		{ID: "acme", Slug: "acme", Name: "Acme", Status: "active", TokenStrategy: "bogus-strategy"},
	}
	if _, err := buildApp(cfg, quietLogger()); err == nil {
		t.Fatal("expected boot error for unregistered tenant token_strategy")
	}
}

// TestBuildApp_TenantTokenStrategy_AcceptsRegistered verifies a valid per-tenant
// strategy (session) is accepted and the app builds.
func TestBuildApp_TenantTokenStrategy_AcceptsRegistered(t *testing.T) {
	cfg := &config.Config{}
	cfg.Tenant.Enabled = true
	cfg.Tenant.Backend = "memory"
	cfg.Tenant.Tenants = []config.TenantSeedConfig{
		{ID: "acme", Slug: "acme", Name: "Acme", Status: "active", TokenStrategy: "session"},
	}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp with valid tenant token_strategy: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
}
