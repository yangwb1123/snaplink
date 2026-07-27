package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
)

// freshTenantStore builds a TenantStore against the integration DB and wipes
// both tables so each test starts clean. RESTART IDENTITY/CASCADE isn't needed
// (no sequences, plain TRUNCATE of both tables in one statement clears the FK
// dependency together).
func freshTenantStore(t *testing.T) *TenantStore {
	t.Helper()
	s, err := NewTenantStore(testConfig(t))
	if err != nil {
		t.Fatalf("NewTenantStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(), "TRUNCATE tenant_domains, tenants"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
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

func TestTenant_PutGetRoundtrip(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
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

func TestTenant_GetMissingReturnsErr(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	_, err := s.GetTenant(context.Background(), "ghost")
	if !errors.Is(err, tenant.ErrTenantNotFound) {
		t.Fatalf("got %v, want ErrTenantNotFound", err)
	}
}

func TestTenant_PutValidates(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	if err := s.PutTenant(context.Background(), &tenant.Tenant{Slug: "no-id"}); !errors.Is(err, tenant.ErrInvalidTenant) {
		t.Fatalf("got %v, want ErrInvalidTenant", err)
	}
}

func TestTenant_PutDefaultsStatus(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, &tenant.Tenant{ID: "t1", Slug: "acme"}); err != nil { // Status unset
		t.Fatalf("PutTenant: %v", err)
	}
	got, _ := s.GetTenant(ctx, "t1")
	if got.Status != tenant.StatusActive {
		t.Fatalf("status = %v, want active default", got.Status)
	}
}

func TestTenant_RegionFieldsRoundtrip(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
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

func TestTenant_RegionFieldsZeroIsUnconstrained(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
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

func TestTenant_EnforceWritesRoundtrip(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, &tenant.Tenant{
		ID: "t1", Slug: "acme", Name: "Acme", Status: tenant.StatusActive,
		HomeRegion: "eu-west-1", EnforceWrites: true,
	}); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if !got.EnforceWrites {
		t.Error("EnforceWrites did not round-trip true via GetTenant")
	}
	// ListTenants is a separate SELECT/Scan path — verify it too.
	list, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(list) != 1 || !list[0].EnforceWrites {
		t.Errorf("EnforceWrites did not round-trip via ListTenants: %+v", list)
	}
	// The zero value (false) round-trips too — the fail-open default.
	if err := s.PutTenant(ctx, &tenant.Tenant{ID: "t2", Slug: "beta", Status: tenant.StatusActive}); err != nil {
		t.Fatalf("PutTenant t2: %v", err)
	}
	got2, _ := s.GetTenant(ctx, "t2")
	if got2.EnforceWrites {
		t.Error("EnforceWrites zero value not false")
	}
}

func TestTenant_SuspendedStatusRoundtrip(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, &tenant.Tenant{ID: "t1", Slug: "acme", Status: tenant.StatusSuspended}); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Status != tenant.StatusSuspended {
		t.Errorf("status = %v, want suspended", got.Status)
	}
}

func TestTenant_PutPreservesCreatedAt(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
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

func TestTenant_PutSlugConflictRejected(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Different ID, same slug → unique constraint violation surfaces as
	// ErrTenantExists (SQLSTATE 23505 on the slug UNIQUE constraint).
	err := s.PutTenant(ctx, mkTenant("t2", "acme"))
	if !errors.Is(err, tenant.ErrTenantExists) {
		t.Fatalf("got %v, want ErrTenantExists", err)
	}
}

func TestTenant_ListSorted(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	for _, id := range []string{"t3", "t1", "t2"} {
		if err := s.PutTenant(ctx, mkTenant(id, id+"-slug")); err != nil {
			t.Fatalf("PutTenant %s: %v", id, err)
		}
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

func TestTenant_DeleteCascadesDomains(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	if err := s.PutDomain(ctx, mkDomain("acme.com", "t1")); err != nil {
		t.Fatalf("PutDomain: %v", err)
	}
	if err := s.PutDomain(ctx, mkDomain("portal.acme.com", "t1")); err != nil {
		t.Fatalf("PutDomain: %v", err)
	}

	if err := s.DeleteTenant(ctx, "t1"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if _, err := s.GetTenant(ctx, "t1"); !errors.Is(err, tenant.ErrTenantNotFound) {
		t.Errorf("tenant survives delete: %v", err)
	}
	// FOREIGN KEY ... CASCADE should have wiped the two domain rows.
	if _, err := s.GetDomain(ctx, "acme.com"); !errors.Is(err, tenant.ErrDomainNotFound) {
		t.Errorf("domain survives tenant delete: %v", err)
	}
	if _, err := s.GetDomain(ctx, "portal.acme.com"); !errors.Is(err, tenant.ErrDomainNotFound) {
		t.Errorf("portal domain survives tenant delete: %v", err)
	}
}

// --- Domains ---

func TestDomain_RoundtripCaseInsensitiveLookup(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
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
		if got.DefaultClientID != "default-client" || !got.IsApex {
			t.Errorf("domain scalars mismatch: %+v", got)
		}
		if got.Branding["logo"] != "https://cdn/logo.png" {
			t.Errorf("branding mismatch: %v", got.Branding)
		}
	}
}

func TestDomain_GetTrailingDotNormalised(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	if err := s.PutDomain(ctx, mkDomain("acme.com", "t1")); err != nil {
		t.Fatalf("PutDomain: %v", err)
	}
	if _, err := s.GetDomain(ctx, "acme.com."); err != nil {
		t.Fatalf("trailing-dot lookup: %v", err)
	}
}

func TestDomain_GetMissingReturnsErr(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	if _, err := s.GetDomain(context.Background(), "ghost.example.com"); !errors.Is(err, tenant.ErrDomainNotFound) {
		t.Fatalf("got %v, want ErrDomainNotFound", err)
	}
}

func TestDomain_PutRejectsUnknownTenant(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	err := s.PutDomain(context.Background(), mkDomain("acme.com", "ghost-tenant"))
	if !errors.Is(err, tenant.ErrTenantNotFound) {
		t.Fatalf("got %v, want ErrTenantNotFound", err)
	}
}

func TestDomain_PutHostnameConflictRejected(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("PutTenant t1: %v", err)
	}
	if err := s.PutTenant(ctx, mkTenant("t2", "beta")); err != nil {
		t.Fatalf("PutTenant t2: %v", err)
	}
	if err := s.PutDomain(ctx, mkDomain("acme.com", "t1")); err != nil {
		t.Fatalf("PutDomain: %v", err)
	}
	err := s.PutDomain(ctx, mkDomain("acme.com", "t2"))
	if !errors.Is(err, tenant.ErrDomainExists) {
		t.Fatalf("got %v, want ErrDomainExists", err)
	}
}

// TestDomain_PutConcurrentCrossTenantClaimIsSerialized races two PutDomain
// calls claiming the SAME fresh hostname for two DIFFERENT tenants. Before the
// SERIALIZABLE-wrapped fix, PutDomain ran verifyTenantExists +
// checkDomainConflict + the INSERT as three independent READ COMMITTED
// statements: both goroutines could read the hostname as unclaimed before
// either committed its INSERT ... ON CONFLICT DO UPDATE, so the second writer
// silently overwrote the first's tenant_id — a cross-tenant domain hijack
// with NO error returned to either caller. Exactly one call must win the
// claim; the other must observe ErrDomainExists (never both nil).
func TestDomain_PutConcurrentCrossTenantClaimIsSerialized(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("race-t1", "race-acme")); err != nil {
		t.Fatalf("PutTenant race-t1: %v", err)
	}
	if err := s.PutTenant(ctx, mkTenant("race-t2", "race-beta")); err != nil {
		t.Fatalf("PutTenant race-t2: %v", err)
	}

	const attempts = 10
	for i := 0; i < attempts; i++ {
		host := "race.example.com"
		tenants := [2]string{"race-t1", "race-t2"}
		errs := [2]error{}
		var wg sync.WaitGroup
		start := make(chan struct{})
		for j := range tenants {
			j := j
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[j] = s.PutDomain(ctx, mkDomain(host, tenants[j]))
			}()
		}
		close(start)
		wg.Wait()

		successes := 0
		for _, err := range errs {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, tenant.ErrDomainExists):
				// Expected loser outcome.
			default:
				t.Fatalf("attempt %d: unexpected PutDomain error: %v", i, err)
			}
		}
		if successes != 1 {
			t.Fatalf("attempt %d: got %d successful concurrent claims for %q, want exactly 1 (errs=%v) — cross-tenant domain hijack", i, successes, host, errs)
		}

		got, err := s.GetDomain(ctx, host)
		if err != nil {
			t.Fatalf("attempt %d: GetDomain after race: %v", i, err)
		}
		if got.TenantID != "race-t1" && got.TenantID != "race-t2" {
			t.Fatalf("attempt %d: domain owner %q is neither racer", i, got.TenantID)
		}
		if err := s.DeleteDomain(ctx, host); err != nil {
			t.Fatalf("attempt %d: cleanup DeleteDomain: %v", i, err)
		}
	}
}

func TestDomain_PutSameTenantUpdateAllowed(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	first := mkDomain("acme.com", "t1")
	first.DefaultClientID = "first-default"
	if err := s.PutDomain(ctx, first); err != nil {
		t.Fatalf("first PutDomain: %v", err)
	}
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

func TestDomain_ListByTenant(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("PutTenant t1: %v", err)
	}
	if err := s.PutTenant(ctx, mkTenant("t2", "beta")); err != nil {
		t.Fatalf("PutTenant t2: %v", err)
	}
	for _, d := range []*tenant.Domain{
		mkDomain("acme.com", "t1"),
		mkDomain("portal.acme.com", "t1"),
		mkDomain("beta.io", "t2"),
	} {
		if err := s.PutDomain(ctx, d); err != nil {
			t.Fatalf("PutDomain %s: %v", d.Hostname, err)
		}
	}

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
	// ListDomains returns all three, sorted by hostname.
	all, err := s.ListDomains(ctx)
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(all) != 3 || all[0].Hostname != "acme.com" {
		t.Errorf("ListDomains mismatch: %+v", all)
	}
	// Unknown tenant → empty, non-nil slice.
	empty, err := s.ListDomainsByTenant(ctx, "nobody")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("ListDomainsByTenant(unknown) = (%v, %v), want (empty non-nil, nil)", empty, err)
	}
}

func TestDomain_DeleteIdempotent(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	if err := s.DeleteDomain(context.Background(), "ghost.example.com"); err != nil {
		t.Fatalf("Delete on missing: %v", err)
	}
}

func TestTenant_PingAfterCloseErrors(t *testing.T) {
	t.Parallel()
	s := freshTenantStore(t)
	_ = s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("Ping after Close: want error")
	}
}
