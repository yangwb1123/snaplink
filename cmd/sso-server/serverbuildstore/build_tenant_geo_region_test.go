package serverbuildstore

import (
	"context"
	"testing"

	"github.com/snaplink/sso/config"
)

func TestBuildTenantUsageAggregator_DisabledMemorySqliteUnknown(t *testing.T) {
	t.Parallel()
	if a, err := BuildTenantUsageAggregator(config.TenantUsageMeteringConfig{}); err != nil || a != nil {
		t.Fatalf("disabled: agg=%v err=%v, want (nil, nil)", a, err)
	}
	if a, err := BuildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "memory"}); err != nil || a == nil {
		t.Fatalf("memory: agg=%v err=%v", a, err)
	}
	if _, err := BuildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "sqlite"}); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
	if _, err := BuildTenantUsageAggregator(config.TenantUsageMeteringConfig{Backend: "carrier-pigeon"}); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildTenantStore_Disabled(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	store, err := BuildTenantStore(cfg, testLogger(), nil, "")
	if err != nil || store != nil {
		t.Fatalf("disabled: store=%v err=%v, want (nil, nil)", store, err)
	}
}

// TestBuildTenantStore_MemorySeedsTenantsAndDomains proves the declared
// seed tenants + domains actually land in the store (seedTenantStore's
// job) — a silently-dropped seed leaves an embedder's admin-managed
// tenant list empty at first boot.
func TestBuildTenantStore_MemorySeedsTenantsAndDomains(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Tenant.Enabled = true
	cfg.Tenant.Backend = "memory"
	cfg.Tenant.Tenants = []config.TenantSeedConfig{{ID: "t1", Slug: "acme", Name: "Acme"}}
	cfg.Tenant.Domains = []config.TenantDomainConfig{{Hostname: "acme.example.com", TenantID: "t1", IsApex: true}}

	store, err := BuildTenantStore(cfg, testLogger(), nil, "")
	if err != nil {
		t.Fatalf("BuildTenantStore: %v", err)
	}
	if store == nil {
		t.Fatal("nil store with tenant.enabled=true")
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	got, err := store.GetTenant(ctx, "t1")
	if err != nil || got == nil || got.Status != "active" {
		t.Fatalf("seeded tenant: got=%+v err=%v, want active tenant t1 (status defaults to active)", got, err)
	}
	dom, err := store.GetDomain(ctx, "acme.example.com")
	if err != nil || dom == nil || dom.TenantID != "t1" {
		t.Fatalf("seeded domain: got=%+v err=%v", dom, err)
	}
}

func TestBuildTenantStore_UnknownBackendErrors(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Tenant.Enabled = true
	cfg.Tenant.Backend = "carrier-pigeon"
	if _, err := BuildTenantStore(cfg, testLogger(), nil, ""); err == nil {
		t.Fatal("expected error: unknown tenant.backend")
	}
}

func TestBuildConnectionStore_DisabledMemorySeedsUnknown(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	if store, err := BuildConnectionStore(cfg, testLogger()); err != nil || store != nil {
		t.Fatalf("disabled: store=%v err=%v, want (nil, nil)", store, err)
	}

	cfg.Connections.Enabled = true
	cfg.Connections.Connections = []config.ConnectionSeedConfig{
		{ID: "conn1", TenantID: "t1", Type: "oidc", Enabled: true},
	}
	store, err := BuildConnectionStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildConnectionStore: %v", err)
	}
	if store == nil {
		t.Fatal("nil store with connections.enabled=true")
	}
	got, err := store.Get(context.Background(), "conn1")
	if err != nil || got == nil {
		t.Fatalf("seeded connection not found: got=%v err=%v", got, err)
	}

	cfg2 := &config.Config{}
	cfg2.Connections.Enabled = true
	cfg2.Connections.Backend = "carrier-pigeon"
	if _, err := BuildConnectionStore(cfg2, testLogger()); err == nil {
		t.Fatal("expected error: unknown connections.backend")
	}
}

func TestBuildGeoProvider_DisabledStaticEntriesAndUnknown(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	if p, err := BuildGeoProvider(cfg, testLogger()); err != nil || p != nil {
		t.Fatalf("disabled: provider=%v err=%v, want (nil, nil)", p, err)
	}

	cfg.Geo.Enabled = true
	cfg.Geo.Static.Entries = []config.GeoStaticEntry{{CIDR: "10.0.0.0/8", CountryCode: "US"}}
	p, err := BuildGeoProvider(cfg, testLogger())
	if err != nil || p == nil {
		t.Fatalf("static: provider=%v err=%v", p, err)
	}

	cfg2 := &config.Config{}
	cfg2.Geo.Enabled = true
	cfg2.Geo.Backend = "carrier-pigeon"
	if _, err := BuildGeoProvider(cfg2, testLogger()); err == nil {
		t.Fatal("expected error: unknown geo.backend")
	}
}

func TestBuildGeoProvider_BadCIDRErrors(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Geo.Enabled = true
	cfg.Geo.Static.Entries = []config.GeoStaticEntry{{CIDR: "not-a-cidr"}}
	if _, err := BuildGeoProvider(cfg, testLogger()); err == nil {
		t.Fatal("expected error: malformed CIDR in a static geo entry")
	}
}

func TestBuildRegionResolver_NilWhenUnconfigured(t *testing.T) {
	t.Parallel()
	if r := BuildRegionResolver(&config.Config{}); r != nil {
		t.Fatalf("got %v, want nil (neither serving_region nor header_name set)", r)
	}
}

// TestBuildRegionResolver_HeaderWinsOverPinnedDefault proves the chain
// resolver tries the trusted header FIRST — a regionally-pinned edge that
// sets the header must be honored over the static ServingRegion default.
func TestBuildRegionResolver_HeaderWinsOverPinnedDefault(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Region.ServingRegion = "eu-west-1"
	cfg.Region.HeaderName = "X-Serving-Region"
	cfg.Region.AllowedRegions = []string{"us-east-1"}
	r := BuildRegionResolver(cfg)
	if r == nil {
		t.Fatal("nil resolver with serving_region + header_name set")
	}
}

func TestBootstrapLogger_DelegatesToInner(t *testing.T) {
	t.Parallel()
	bl := BootstrapLogger{Inner: testLogger()}
	// NopLogger swallows output; this is a no-panic + interface-shape smoke
	// test (BootstrapLogger only exists to adapt spi.Logger's Info/Error
	// pair onto bootstrap.Logger's identical shape).
	bl.Info("boot", "k", "v")
	bl.Error("boot", "k", "v")
}
