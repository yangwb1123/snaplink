package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildplatform"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/platform/geo"
)

// -----------------------------------------------------------------------------
// serverbuildstore.BuildSnapshotSubsystem
// -----------------------------------------------------------------------------

// TestBuildSnapshotSubsystem_DisabledReturnsNils — operators who
// don't opt in get zero allocation + no startup cost. Pinned because
// cmd downstream silently no-ops when the returned values are nil
// (admin registration, restore step) — a non-nil return would wire
// the snapshot RPCs without any backend behind them.
func TestBuildSnapshotSubsystem_DisabledReturnsNils(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = false
	pipe, store, err := serverbuildstore.BuildSnapshotSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if pipe != nil || store != nil {
		t.Errorf("pipe=%v store=%v; want both nil", pipe, store)
	}
}

// TestBuildSnapshotSubsystem_InlineStorage — happy path on the
// in-memory backend. Asserts the Pipeline + Storage round-trip a
// trivial snapshot through the Save/Load API.
func TestBuildSnapshotSubsystem_InlineStorage(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "inline"
	pipe, store, err := serverbuildstore.BuildSnapshotSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if pipe == nil || store == nil {
		t.Fatal("pipe or store nil with inline backend")
	}
}

// TestBuildSnapshotSubsystem_FileStorageWithDir — file backend
// happy path. Uses a tempdir so subsequent test runs don't see
// stale files.
func TestBuildSnapshotSubsystem_FileStorageWithDir(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "file"
	cfg.Snapshot.Storage.File.Dir = filepath.Join(t.TempDir(), "snaps")
	pipe, store, err := serverbuildstore.BuildSnapshotSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if pipe == nil || store == nil {
		t.Fatal("pipe or store nil with file backend")
	}
}

// TestBuildSnapshotSubsystem_UnknownBackendErrors — operator typos
// surface at boot rather than silently falling back to file.
func TestBuildSnapshotSubsystem_UnknownBackendErrors(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "s3"
	if _, _, err := serverbuildstore.BuildSnapshotSubsystem(cfg, quietLogger()); err == nil {
		t.Fatal("expected error for unknown storage backend")
	}
}

// TestBuildSnapshotSubsystem_PassphraseRequiresValue — opting into
// passphrase encryption without supplying one is a misconfiguration
// the operator needs to know about at boot time.
func TestBuildSnapshotSubsystem_PassphraseRequiresValue(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "inline"
	cfg.Snapshot.Encryption.Backend = "passphrase"
	if _, _, err := serverbuildstore.BuildSnapshotSubsystem(cfg, quietLogger()); err == nil {
		t.Fatal("expected error for passphrase backend without passphrase")
	}
}

// TestBuildSnapshotSubsystem_PassphraseFromInline — inline
// passphrase happy path. The argon2id+chacha20poly1305 sealer is
// the production-recommended encryption shape per AGENTS.md.
func TestBuildSnapshotSubsystem_PassphraseFromInline(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "inline"
	cfg.Snapshot.Encryption.Backend = "passphrase"
	cfg.Snapshot.Encryption.Passphrase = "correct-horse-battery-staple"
	pipe, _, err := serverbuildstore.BuildSnapshotSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if pipe == nil || pipe.Sealer == nil {
		t.Fatal("pipe.Sealer is nil; passphrase opt-in didn't take effect")
	}
}

// -----------------------------------------------------------------------------
// serverbuildplatform.BuildReleaseSubsystem
// -----------------------------------------------------------------------------

// TestBuildReleaseSubsystem_DisabledReturnsNils — same shape as
// the snapshot disabled guard. Admin Release RPC + Pinner stay
// unwired.
func TestBuildReleaseSubsystem_DisabledReturnsNils(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Releases.Enabled = false
	reg, store, err := serverbuildplatform.BuildReleaseSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if reg != nil || store != nil {
		t.Errorf("reg=%v store=%v; want both nil", reg, store)
	}
}

// TestBuildReleaseSubsystem_MemoryStoreNoopPinner — minimal
// happy path for a dev / CI deployment that wants the Release
// admin RPC mounted without persisting or actually flipping
// artifacts.
func TestBuildReleaseSubsystem_MemoryStoreNoopPinner(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Releases.Enabled = true
	cfg.Releases.Store.Backend = "memory"
	cfg.Releases.Pinner.Backend = "noop"
	reg, store, err := serverbuildplatform.BuildReleaseSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if reg == nil || reg.Store == nil || reg.Pinner == nil {
		t.Fatalf("Registry incomplete: store=%v pinner=%v", reg.Store, reg.Pinner)
	}
	if store == nil {
		t.Error("standalone store handle is nil")
	}
}

// TestBuildReleaseSubsystem_StaticPinnerRequiresBundleDir —
// configuration error that would otherwise silently produce a
// pinner that always errored at flip time.
func TestBuildReleaseSubsystem_StaticPinnerRequiresBundleDir(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Releases.Enabled = true
	cfg.Releases.Store.Backend = "memory"
	cfg.Releases.Pinner.Backend = "static"
	if _, _, err := serverbuildplatform.BuildReleaseSubsystem(cfg, quietLogger()); err == nil {
		t.Fatal("expected error for static pinner without bundle_dir")
	}
}

// TestBuildReleaseSubsystem_UnknownStoreBackendErrors guards
// against silent fallback when operators typo the backend name.
func TestBuildReleaseSubsystem_UnknownStoreBackendErrors(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Releases.Enabled = true
	cfg.Releases.Store.Backend = "redis"
	if _, _, err := serverbuildplatform.BuildReleaseSubsystem(cfg, quietLogger()); err == nil {
		t.Fatal("expected error for unknown release store backend")
	}
}

// -----------------------------------------------------------------------------
// serverbuildstore.BuildTenantStore
// -----------------------------------------------------------------------------

// TestBuildTenantStore_DisabledReturnsNil — multi-tenant deployments
// only; single-tenant cmd gets nil so sso.WithTenantStore is a
// no-op.
func TestBuildTenantStore_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Tenant.Enabled = false
	store, err := serverbuildstore.BuildTenantStore(cfg, quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store != nil {
		t.Errorf("store = %v; want nil", store)
	}
}

// TestBuildTenantStore_SeedsTenantsAndDomains — proves the YAML
// seed lists actually flow into the in-memory store. A regression
// here would leave declared tenants unfindable at runtime even
// though config validation passes.
func TestBuildTenantStore_SeedsTenantsAndDomains(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Tenant.Enabled = true
	cfg.Tenant.Tenants = []config.TenantSeedConfig{
		{ID: "t-a", Slug: "alpha", Name: "Alpha"},
		{ID: "t-b", Slug: "beta", Name: "Beta", Status: "suspended"},
	}
	cfg.Tenant.Domains = []config.TenantDomainConfig{
		{Hostname: "alpha.example.com", TenantID: "t-a"},
	}
	store, err := serverbuildstore.BuildTenantStore(cfg, quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if store == nil {
		t.Fatal("store is nil despite Enabled=true")
	}
	ctx := context.Background()
	a, err := store.GetTenant(ctx, "t-a")
	if err != nil {
		t.Fatalf("get t-a: %v", err)
	}
	if a.Status != tenant.StatusActive {
		t.Errorf("t-a status = %q; want active (empty seed → default)", a.Status)
	}
	b, err := store.GetTenant(ctx, "t-b")
	if err != nil {
		t.Fatalf("get t-b: %v", err)
	}
	if b.Status != tenant.StatusSuspended {
		t.Errorf("t-b status = %q; want suspended", b.Status)
	}
	dom, err := store.GetDomain(ctx, "alpha.example.com")
	if err != nil {
		t.Fatalf("get domain: %v", err)
	}
	if dom.TenantID != "t-a" {
		t.Errorf("domain tenant = %q; want t-a", dom.TenantID)
	}
}

// TestBuildTenantStore_UnknownBackendErrors guards against the
// silent-fallback trap if a future backend is added without
// updating the switch.
func TestBuildTenantStore_UnknownBackendErrors(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Tenant.Enabled = true
	cfg.Tenant.Backend = "postgres"
	if _, err := serverbuildstore.BuildTenantStore(cfg, quietLogger(), nil, ""); err == nil {
		t.Fatal("expected error for unknown tenant backend")
	}
}

// -----------------------------------------------------------------------------
// serverbuildstore.BuildGeoProvider
// -----------------------------------------------------------------------------

// TestBuildGeoProvider_DisabledReturnsNil — geo is a UX hint;
// operators who don't wire it get nil so sso.WithGeoProvider
// no-ops.
func TestBuildGeoProvider_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Geo.Enabled = false
	p, err := serverbuildstore.BuildGeoProvider(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if p != nil {
		t.Errorf("provider = %v; want nil", p)
	}
}

// TestBuildGeoProvider_StaticSeedsCIDREntries — declared
// static.entries must actually populate the provider. Failure
// here would silently make login responses omit country_code /
// recommended_language enrichment.
func TestBuildGeoProvider_StaticSeedsCIDREntries(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Geo.Enabled = true
	cfg.Geo.Static.Entries = []config.GeoStaticEntry{
		{CIDR: "10.0.0.0/8", CountryCode: "US", RecommendedLanguage: "en-US"},
		{CIDR: "2001:db8::/32", CountryCode: "JP", RecommendedLanguage: "ja-JP"},
	}
	p, err := serverbuildstore.BuildGeoProvider(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if p == nil {
		t.Fatal("provider nil despite Enabled=true with seeded entries")
	}
	info, err := geo.LookupString(context.Background(), p, "10.1.2.3")
	if err != nil {
		t.Fatalf("lookup 10.1.2.3: %v", err)
	}
	if info.CountryCode != "US" {
		t.Errorf("country = %q; want US (10.0.0.0/8 entry didn't seed)", info.CountryCode)
	}
}

// TestBuildGeoProvider_BadCIDRSurfaces — malformed CIDR fails at
// boot, not at first request.
func TestBuildGeoProvider_BadCIDRSurfaces(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Geo.Enabled = true
	cfg.Geo.Static.Entries = []config.GeoStaticEntry{
		{CIDR: "not-a-cidr", CountryCode: "US"},
	}
	if _, err := serverbuildstore.BuildGeoProvider(cfg, quietLogger()); err == nil {
		t.Fatal("expected error for malformed CIDR")
	}
}

// TestBuildGeoProvider_UnknownBackendErrors guards against
// silent-fallback if a future backend is added without updating
// the switch.
func TestBuildGeoProvider_UnknownBackendErrors(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Geo.Enabled = true
	cfg.Geo.Backend = "carrier-pigeon"
	if _, err := serverbuildstore.BuildGeoProvider(cfg, quietLogger()); err == nil {
		t.Fatal("expected error for unknown geo backend")
	}
}
