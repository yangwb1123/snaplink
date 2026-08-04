package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant"

	_ "modernc.org/sqlite"
)

func TestStore_ListDomains(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutTenant(ctx, mkTenant("t2", "beta"))
	_ = s.PutDomain(ctx, mkDomain("acme.com", "t1"))
	_ = s.PutDomain(ctx, mkDomain("portal.acme.com", "t1"))
	_ = s.PutDomain(ctx, mkDomain("beta.io", "t2"))

	all, err := s.ListDomains(ctx)
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListDomains = %d, want 3", len(all))
	}
	// Query is ORDER BY hostname — assert the ascending order.
	wantOrder := []string{"acme.com", "beta.io", "portal.acme.com"}
	for i, d := range all {
		if d.Hostname != wantOrder[i] {
			t.Errorf("position %d = %q, want %q", i, d.Hostname, wantOrder[i])
		}
	}
}

func TestStore_ListDomainsEmpty(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	all, err := s.ListDomains(context.Background())
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("empty store returned %d domains", len(all))
	}
}

func TestNewWithDB_RoundtripAndCallerOwnsConn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "withdb.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	s, err := NewWithDB(db)
	if err != nil {
		t.Fatalf("NewWithDB: %v", err)
	}
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Slug != "acme" {
		t.Errorf("slug=%q", got.Slug)
	}

	// DB() exposes the same handle the caller passed in; it must remain
	// usable (the store does not own it under NewWithDB).
	if s.DB() != db {
		t.Error("DB() did not return the caller-owned handle")
	}
	if err := s.DB().PingContext(ctx); err != nil {
		t.Errorf("caller-owned DB unusable: %v", err)
	}
}

func TestStore_DBNilAfterClose(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	if s.DB() == nil {
		t.Fatal("DB() nil before close")
	}
	_ = s.Close()
	if s.DB() != nil {
		t.Error("DB() should be nil after Close")
	}
	// Close is idempotent.
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestStore_CloseNilReceiverSafe(t *testing.T) {
	t.Parallel()
	var s *Store
	if err := s.Close(); err != nil {
		t.Errorf("Close on nil store: %v", err)
	}
}

func TestStore_PingNilStoreErrors(t *testing.T) {
	t.Parallel()
	var s *Store
	if err := s.Ping(context.Background()); err == nil {
		t.Error("Ping on nil store: want error")
	}
}

func TestStore_BrandingCompareAndSwapPreservesTenantSettings(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	base := mkTenant("t1", "acme")
	base.Settings = map[string]string{"locale": "en-US", "feature": "enabled"}
	if err := s.PutTenant(ctx, base); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	first, err := s.PutBranding(ctx, "t1", map[string]string{"brand_name": "Acme"}, "0")
	if err != nil || first.Version != "1" {
		t.Fatalf("first branding write = (%+v, %v)", first, err)
	}
	if _, err := s.PutBranding(ctx, "t1", map[string]string{"brand_name": "Stale"}, "0"); !errors.Is(err, tenant.ErrBrandingPrecondition) {
		t.Fatalf("stale branding write = %v, want precondition failure", err)
	}
	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Settings["locale"] != "en-US" || got.Settings["feature"] != "enabled" {
		t.Fatalf("branding write changed tenant settings: %v", got.Settings)
	}
}

// Compile-time guard kept alongside the extra coverage so a Store
// signature drift trips here too.
var _ tenant.Store = (*Store)(nil)
var _ tenant.BrandingStore = (*Store)(nil)
