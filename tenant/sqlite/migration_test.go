package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/migrate"
	"github.com/snaplink/sso/tenant"
)

// TestMigration_StampsHeadAndKeepsCascade proves the tenant backend records
// the current head schema version and that the ON DELETE CASCADE foreign
// key survives running through the migration runner (deleting a tenant
// removes its domains).
func TestMigration_StampsHeadAndKeepsCascade(t *testing.T) {
	ctx := context.Background()
	s, err := New("file:" + filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	// A fresh DB applies the whole migration set; head is the last version.
	head := migrations[len(migrations)-1].Version
	if v, _ := migrate.CurrentVersion(ctx, s.db, "tenant"); v != head {
		t.Errorf("version = %d, want %d", v, head)
	}

	if err := s.PutTenant(ctx, &tenant.Tenant{ID: "t1", Slug: "t1", Name: "T1", Status: tenant.StatusActive}); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	if err := s.PutDomain(ctx, &tenant.Domain{Hostname: "t1.example.com", TenantID: "t1"}); err != nil {
		t.Fatalf("PutDomain: %v", err)
	}
	if err := s.DeleteTenant(ctx, "t1"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	// CASCADE: the domain must be gone with its tenant.
	if _, err := s.GetDomain(ctx, "t1.example.com"); err == nil {
		t.Error("domain survived tenant delete — ON DELETE CASCADE not in effect after migration")
	}
}

// TestMigration_V2NoOpsOnV1PopulatedDB proves the v2 residency migration
// applies forward on a database that already carries v1 (baseline) schema
// + data, without disturbing the existing row, and backfills the new
// columns to their unconstrained zero value. This is the populated-DB
// no-op+stamp contract: a v1 deployment upgrading to a v2 binary gains the
// columns, existing tenants stay byte-compatible (empty HomeRegion / nil
// AllowedRegions), and the version stamps to 2.
func TestMigration_V2NoOpsOnV1PopulatedDB(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "v1.db")

	// Stand up a DB at v1 ONLY (baseline schema), seed a tenant the old way
	// (no region columns exist yet), then close.
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatalf("pragma: %v", err)
	}
	v1Only := []migrate.Migration{migrations[0]} // baseline only
	if err := migrate.Run(ctx, db, "tenant", v1Only); err != nil {
		t.Fatalf("v1 migrate: %v", err)
	}
	if v, _ := migrate.CurrentVersion(ctx, db, "tenant"); v != 1 {
		t.Fatalf("pre-upgrade version = %d, want 1", v)
	}
	now := int64(1)
	if _, err := db.ExecContext(ctx, `
        INSERT INTO tenants (id, slug, name, status, settings_json, created_at, updated_at)
        VALUES ('legacy', 'legacy', 'Legacy', 'active', '', ?, ?)`, now, now); err != nil {
		t.Fatalf("seed legacy tenant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen via the store, which runs the FULL migration set. v1 is already
	// recorded so the runner skips it and applies the rest forward (v2 — the
	// residency backfill this test asserts — plus any later migrations),
	// stamping to head.
	s, err := New(dsn)
	if err != nil {
		t.Fatalf("New (upgrade): %v", err)
	}
	defer func() { _ = s.Close() }()

	head := migrations[len(migrations)-1].Version
	if v, _ := migrate.CurrentVersion(ctx, s.db, "tenant"); v != head {
		t.Errorf("post-upgrade version = %d, want %d", v, head)
	}

	// The pre-existing row survives + backfills to the unconstrained zero
	// value via the column DEFAULTs.
	got, err := s.GetTenant(ctx, "legacy")
	if err != nil {
		t.Fatalf("GetTenant(legacy): %v", err)
	}
	if got.HomeRegion != "" || got.AllowedRegions != nil {
		t.Errorf("backfilled legacy tenant not unconstrained: home=%q allowed=%v", got.HomeRegion, got.AllowedRegions)
	}

	// And the new columns are writable post-upgrade.
	if err := s.PutTenant(ctx, &tenant.Tenant{
		ID: "legacy", Slug: "legacy", Name: "Legacy", Status: tenant.StatusActive,
		HomeRegion: "eu-west-1", AllowedRegions: []string{"eu-west-1"},
	}); err != nil {
		t.Fatalf("PutTenant post-upgrade: %v", err)
	}
	upd, _ := s.GetTenant(ctx, "legacy")
	if upd.HomeRegion != "eu-west-1" || len(upd.AllowedRegions) != 1 {
		t.Errorf("region write post-upgrade failed: %+v", upd)
	}
}

// TestMigration_V3NoOpsOnV2PopulatedDB proves the v3 enforce_writes
// migration applies forward on a database already carrying v1+v2 schema +
// data, without disturbing the existing row, and backfills the new column to
// its fail-open zero value (false). Mirrors the v2 no-op test: a v2
// deployment upgrading to a v3 binary gains the column, existing tenants stay
// byte-compatible (EnforceWrites false), and the version stamps to 3.
func TestMigration_V3NoOpsOnV2PopulatedDB(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "v2.db")

	// Stand up a DB at v1+v2 ONLY (baseline + residency regions), seed a
	// tenant with region fields but no enforce_writes column, then close.
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatalf("pragma: %v", err)
	}
	v1v2 := []migrate.Migration{migrations[0], migrations[1]} // baseline + v2
	if err := migrate.Run(ctx, db, "tenant", v1v2); err != nil {
		t.Fatalf("v1+v2 migrate: %v", err)
	}
	if v, _ := migrate.CurrentVersion(ctx, db, "tenant"); v != 2 {
		t.Fatalf("pre-upgrade version = %d, want 2", v)
	}
	now := int64(1)
	if _, err := db.ExecContext(ctx, `
        INSERT INTO tenants (id, slug, name, status, settings_json, home_region, allowed_regions_json, created_at, updated_at)
        VALUES ('legacy', 'legacy', 'Legacy', 'active', '', 'eu-west-1', '["eu-west-1"]', ?, ?)`, now, now); err != nil {
		t.Fatalf("seed v2 tenant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen via the store, which runs the FULL migration set (v1+v2+v3).
	// v1+v2 are already recorded so the runner applies only v3.
	s, err := New(dsn)
	if err != nil {
		t.Fatalf("New (upgrade): %v", err)
	}
	defer func() { _ = s.Close() }()

	if v, _ := migrate.CurrentVersion(ctx, s.db, "tenant"); v != 3 {
		t.Errorf("post-upgrade version = %d, want 3", v)
	}

	// The pre-existing row survives, keeps its v2 region fields, and
	// backfills enforce_writes to the fail-open zero value (false).
	got, err := s.GetTenant(ctx, "legacy")
	if err != nil {
		t.Fatalf("GetTenant(legacy): %v", err)
	}
	if got.HomeRegion != "eu-west-1" || len(got.AllowedRegions) != 1 {
		t.Errorf("v2 region fields disturbed by v3: %+v", got)
	}
	if got.EnforceWrites {
		t.Errorf("backfilled legacy tenant not fail-open: EnforceWrites=true")
	}

	// And the new column is writable post-upgrade.
	if err := s.PutTenant(ctx, &tenant.Tenant{
		ID: "legacy", Slug: "legacy", Name: "Legacy", Status: tenant.StatusActive,
		HomeRegion: "eu-west-1", AllowedRegions: []string{"eu-west-1"}, EnforceWrites: true,
	}); err != nil {
		t.Fatalf("PutTenant post-upgrade: %v", err)
	}
	upd, _ := s.GetTenant(ctx, "legacy")
	if !upd.EnforceWrites {
		t.Errorf("enforce_writes write post-upgrade failed: %+v", upd)
	}
}

// TestMigration_RerunIsIdempotent proves running the full set twice (a
// replica reboot) is a no-op — the version stays at head and no error.
func TestMigration_RerunIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "rerun.db")
	s1, err := New(dsn)
	if err != nil {
		t.Fatalf("New 1: %v", err)
	}
	head := migrations[len(migrations)-1].Version
	if err := s1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}
	s2, err := New(dsn)
	if err != nil {
		t.Fatalf("New 2 (rerun): %v", err)
	}
	defer func() { _ = s2.Close() }()
	if v, _ := migrate.CurrentVersion(ctx, s2.db, "tenant"); v != head {
		t.Errorf("rerun version = %d, want %d", v, head)
	}
}
