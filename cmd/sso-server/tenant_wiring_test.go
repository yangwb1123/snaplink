package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/shared/core"
)

// TestBuildApp_RefreshRotationGrace_BuildsCleanly verifies a configured refresh
// rotation grace window is accepted by buildApp (the option only applies when
// the refresh store is enabled and the window > 0).
func TestBuildApp_RefreshRotationGrace_BuildsCleanly(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	a, err := serverbuildstore.BuildTenantUsageAggregator(config.TenantUsageMeteringConfig{})
	if err != nil {
		t.Fatalf("disabled build: %v", err)
	}
	if a != nil {
		t.Fatalf("expected nil aggregator when backend empty, got %T", a)
	}
}

func TestBuildTenantUsageAggregator_Memory(t *testing.T) {
	t.Parallel()
	a, err := serverbuildstore.BuildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "memory"})
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if a == nil {
		t.Fatal("memory aggregator nil")
	}
}

func TestBuildTenantUsageAggregator_SQLiteNeedsDSN(t *testing.T) {
	t.Parallel()
	if _, err := serverbuildstore.BuildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "sqlite"}); err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildTenantUsageAggregator_SQLiteOpensFile(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db") + "?_journal=WAL"
	a, err := serverbuildstore.BuildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if a == nil {
		t.Fatal("sqlite aggregator nil")
	}
}

func TestBuildTenantUsageAggregator_UnknownBackend(t *testing.T) {
	t.Parallel()
	if _, err := serverbuildstore.BuildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "bogus"}); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

// TestBuildApp_TenantTokenStrategy_RejectsUnregistered verifies an unregistered
// per-tenant token_strategy fails loud at boot (it would break login at runtime).
func TestBuildApp_TenantTokenStrategy_RejectsUnregistered(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestBuildApp_TenantResourceQuotaInjectsAndStops(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Tenant.Enabled = true
	cfg.Tenant.Backend = "memory"
	cfg.Tenant.Tenants = []config.TenantSeedConfig{{ID: "acme", Slug: "acme", Name: "Acme"}}
	cfg.Tenant.ResourceQuota = config.TenantResourceQuotaConfig{
		Backend: "memory",
		Limits:  []config.TenantQuotaSeedConfig{{TenantID: "acme", MaxClients: 1}},
	}
	cfg.ClientRegistration.Enabled = true
	cfg.ClientRegistration.InitialAccessToken = "iat"
	cfg.ClientRegistration.DefaultActive = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)
	if a.tenantQuotaStop == nil {
		t.Fatal("tenant quota cleanup lifecycle was not retained")
	}
	if _, ok := a.sessionMgr.(core.TenantSessionQuotaReconciler); !ok {
		t.Fatalf("session manager %T does not own quota lifecycle", a.sessionMgr)
	}
	httpServer := httptest.NewServer(a.server.Handler())
	defer httpServer.Close()
	if status := postQuotaRegistration(t, httpServer.URL); status != http.StatusCreated {
		t.Fatalf("first registration status=%d, want 201", status)
	}
	if status := postQuotaRegistration(t, httpServer.URL); status != http.StatusForbidden {
		t.Fatalf("second registration status=%d, want 403 quota_exceeded", status)
	}
}

func postQuotaRegistration(t *testing.T, baseURL string) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"client_name": "quota-client", "tenant_id": "acme",
		"redirect_uris": []string{"https://app.example.com/cb"},
	})
	if err != nil {
		t.Fatalf("marshal registration: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/register", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new registration request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer iat")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestBuildApp_MultiReplicaAlwaysRejectsMemoryTenantQuota(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Server.Topology.Mode = config.TopologyModeMulti
	cfg.Server.Topology.AllowPerPodState = true
	cfg.Tenant.Enabled = true
	cfg.Tenant.Backend = "memory"
	cfg.Tenant.ResourceQuota.Backend = "memory"
	if _, err := buildApp(cfg, quietLogger()); err == nil {
		t.Fatal("multi-replica memory quota should fail even with allow_per_pod_state")
	}
}
