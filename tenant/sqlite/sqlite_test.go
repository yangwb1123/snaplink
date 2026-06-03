package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/tenant"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "tenant.db") + "?_journal=WAL&_busy_timeout=5000"
	s, err := New(dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mkTenant(id, slug string) *tenant.Tenant {
	return &tenant.Tenant{
		ID:       id,
		Slug:     slug,
		Name:     "Acme " + slug,
		Status:   tenant.StatusActive,
		Settings: map[string]string{"locale": "en-US", "tier": "pro"},
	}
}

func mkDomain(host, tenantID string) *tenant.Domain {
	return &tenant.Domain{
		Hostname:        host,
		TenantID:        tenantID,
		DefaultClientID: "default-client",
		IsApex:          true,
		Branding:        map[string]string{"logo": "https://cdn/logo.png"},
	}
}

func TestStore_TenantRoundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	want := mkTenant("t1", "acme")

	if err := s.PutTenant(ctx, want); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.ID != want.ID || got.Slug != want.Slug || got.Name != want.Name || got.Status != want.Status {
		t.Errorf("mismatch: got %+v want %+v", got, want)
	}
	if got.Settings["locale"] != "en-US" || got.Settings["tier"] != "pro" {
		t.Errorf("settings mismatch: %v", got.Settings)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt not set")
	}
}

func TestStore_TenantRegionFieldsRoundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	want := &tenant.Tenant{
		ID:             "t1",
		Slug:           "acme",
		Name:           "Acme",
		Status:         tenant.StatusActive,
		HomeRegion:     "eu-west-1",
		AllowedRegions: []string{"eu-west-1", "eu-central-1"},
	}
	if err := s.PutTenant(ctx, want); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}

	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.HomeRegion != "eu-west-1" {
		t.Errorf("HomeRegion=%q", got.HomeRegion)
	}
	if len(got.AllowedRegions) != 2 || got.AllowedRegions[0] != "eu-west-1" || got.AllowedRegions[1] != "eu-central-1" {
		t.Errorf("AllowedRegions=%v", got.AllowedRegions)
	}

	// ListTenants must surface the same fields (separate SELECT path).
	list, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(list) != 1 || list[0].HomeRegion != "eu-west-1" || len(list[0].AllowedRegions) != 2 {
		t.Errorf("list region fields mismatch: %+v", list)
	}
}

func TestStore_TenantRegionFieldsZeroIsUnconstrained(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// A tenant persisted without region fields must round-trip to the zero
	// value: home_region '' (DEFAULT) and allowed_regions_json '[]' decode
	// back to "" / nil (backward-compatible with pre-residency rows).
	if err := s.PutTenant(ctx, &tenant.Tenant{ID: "t1", Slug: "acme", Name: "Acme", Status: tenant.StatusActive}); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.HomeRegion != "" || got.AllowedRegions != nil {
		t.Errorf("region fields not zero-valued: home=%q allowed=%v", got.HomeRegion, got.AllowedRegions)
	}
}

func TestStore_GetTenantMissingReturnsErr(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetTenant(context.Background(), "ghost")
	if !errors.Is(err, tenant.ErrTenantNotFound) {
		t.Fatalf("got %v, want ErrTenantNotFound", err)
	}
}

func TestStore_PutTenantValidates(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutTenant(context.Background(), &tenant.Tenant{Slug: "no-id"}); !errors.Is(err, tenant.ErrInvalidTenant) {
		t.Fatalf("got %v, want ErrInvalidTenant", err)
	}
}

func TestStore_PutTenantDefaultsStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t1 := &tenant.Tenant{ID: "t1", Slug: "acme"} // Status unset
	if err := s.PutTenant(ctx, t1); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	got, _ := s.GetTenant(ctx, "t1")
	if got.Status != tenant.StatusActive {
		t.Fatalf("status = %v, want active default", got.Status)
	}
}

func TestStore_PutTenantPreservesCreatedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	first, _ := s.GetTenant(ctx, "t1")
	time.Sleep(2 * time.Millisecond)

	updated := mkTenant("t1", "acme-renamed")
	updated.Name = "Acme Renamed"
	if err := s.PutTenant(ctx, updated); err != nil {
		t.Fatalf("update Put: %v", err)
	}
	second, _ := s.GetTenant(ctx, "t1")
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("CreatedAt changed on update: was %v, now %v", first.CreatedAt, second.CreatedAt)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Errorf("UpdatedAt did not advance: first %v, second %v", first.UpdatedAt, second.UpdatedAt)
	}
	if second.Slug != "acme-renamed" {
		t.Errorf("slug not updated: %v", second.Slug)
	}
}

func TestStore_PutTenantSlugConflictRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Different ID, same slug → unique constraint violation surfaces
	// as ErrTenantExists.
	err := s.PutTenant(ctx, mkTenant("t2", "acme"))
	if !errors.Is(err, tenant.ErrTenantExists) {
		t.Fatalf("got %v, want ErrTenantExists", err)
	}
}

func TestStore_ListTenantsSorted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// Insert in reverse order; List should sort by id ascending.
	for _, id := range []string{"t3", "t1", "t2"} {
		_ = s.PutTenant(ctx, mkTenant(id, id+"-slug"))
	}
	out, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	for i, want := range []string{"t1", "t2", "t3"} {
		if out[i].ID != want {
			t.Errorf("out[%d] = %v, want %v", i, out[i].ID, want)
		}
	}
}

func TestStore_DeleteTenantCascadesDomains(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutDomain(ctx, mkDomain("acme.com", "t1"))
	_ = s.PutDomain(ctx, mkDomain("portal.acme.com", "t1"))

	if err := s.DeleteTenant(ctx, "t1"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if _, err := s.GetTenant(ctx, "t1"); !errors.Is(err, tenant.ErrTenantNotFound) {
		t.Errorf("tenant survives delete: %v", err)
	}
	// FOREIGN KEY ... CASCADE should have wiped the two domain rows
	// — orphan rows would route to a 404 tenant on next request.
	if _, err := s.GetDomain(ctx, "acme.com"); !errors.Is(err, tenant.ErrDomainNotFound) {
		t.Errorf("domain survives tenant delete: %v", err)
	}
	if _, err := s.GetDomain(ctx, "portal.acme.com"); !errors.Is(err, tenant.ErrDomainNotFound) {
		t.Errorf("portal domain survives tenant delete: %v", err)
	}
}

// --- Domains ---

func TestStore_DomainRoundtripWithCaseInsensitiveLookup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	if err := s.PutDomain(ctx, mkDomain("Acme.com", "t1")); err != nil {
		t.Fatalf("PutDomain: %v", err)
	}
	for _, lookup := range []string{"acme.com", "ACME.COM", "Acme.Com"} {
		got, err := s.GetDomain(ctx, lookup)
		if err != nil {
			t.Errorf("GetDomain(%q): %v", lookup, err)
			continue
		}
		if got.Hostname != "acme.com" {
			t.Errorf("hostname not normalized: %v", got.Hostname)
		}
	}
}

func TestStore_GetDomainTrailingDotNormalised(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutDomain(ctx, mkDomain("acme.com", "t1"))
	if _, err := s.GetDomain(ctx, "acme.com."); err != nil {
		t.Fatalf("trailing-dot lookup: %v", err)
	}
}

func TestStore_PutDomainRejectsUnknownTenant(t *testing.T) {
	s := newTestStore(t)
	err := s.PutDomain(context.Background(), mkDomain("acme.com", "ghost-tenant"))
	if !errors.Is(err, tenant.ErrTenantNotFound) {
		t.Fatalf("got %v, want ErrTenantNotFound", err)
	}
}

func TestStore_PutDomainHostnameConflictRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutTenant(ctx, mkTenant("t2", "beta"))
	_ = s.PutDomain(ctx, mkDomain("acme.com", "t1"))

	err := s.PutDomain(ctx, mkDomain("acme.com", "t2"))
	if !errors.Is(err, tenant.ErrDomainExists) {
		t.Fatalf("got %v, want ErrDomainExists", err)
	}
}

func TestStore_PutDomainSameTenantUpdateAllowed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	first := mkDomain("acme.com", "t1")
	first.DefaultClientID = "first-default"
	_ = s.PutDomain(ctx, first)

	updated := mkDomain("acme.com", "t1")
	updated.DefaultClientID = "second-default"
	if err := s.PutDomain(ctx, updated); err != nil {
		t.Fatalf("update Put: %v", err)
	}
	got, _ := s.GetDomain(ctx, "acme.com")
	if got.DefaultClientID != "second-default" {
		t.Errorf("DefaultClientID not updated: %v", got.DefaultClientID)
	}
}

func TestStore_ListDomainsByTenant(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutTenant(ctx, mkTenant("t2", "beta"))
	_ = s.PutDomain(ctx, mkDomain("acme.com", "t1"))
	_ = s.PutDomain(ctx, mkDomain("portal.acme.com", "t1"))
	_ = s.PutDomain(ctx, mkDomain("beta.io", "t2"))

	t1Domains, err := s.ListDomainsByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("ListDomainsByTenant t1: %v", err)
	}
	if len(t1Domains) != 2 {
		t.Fatalf("t1 domains = %d, want 2", len(t1Domains))
	}
	for _, d := range t1Domains {
		if d.TenantID != "t1" {
			t.Errorf("filter leaked tenant %v", d.TenantID)
		}
	}
}

func TestStore_DeleteDomainIdempotent(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeleteDomain(context.Background(), "ghost.example.com"); err != nil {
		t.Fatalf("Delete on missing: %v", err)
	}
}

func TestStore_PingAfterCloseErrors(t *testing.T) {
	s := newTestStore(t)
	_ = s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("Ping after Close: want error")
	}
}
