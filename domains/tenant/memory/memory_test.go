package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/domains/tenant/memory"
)

func mkTenant(id, slug string) *tenant.Tenant {
	return &tenant.Tenant{ID: id, Slug: slug, Name: slug}
}

func mkDomain(host, tenantID string) *tenant.Domain {
	return &tenant.Domain{Hostname: host, TenantID: tenantID}
}

func TestPutGetTenant_Roundtrip(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Slug != "acme" {
		t.Errorf("slug=%q", got.Slug)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt not stamped")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt not stamped")
	}
	if got.Status != tenant.StatusActive {
		t.Errorf("default status=%q", got.Status)
	}
}

func TestPutGetTenant_RegionFieldsRoundtrip(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	want := &tenant.Tenant{
		ID:             "t1",
		Slug:           "acme",
		Name:           "acme",
		HomeRegion:     "eu-west-1",
		AllowedRegions: []string{"eu-west-1", "eu-central-1"},
	}
	if err := s.PutTenant(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HomeRegion != "eu-west-1" {
		t.Errorf("HomeRegion=%q", got.HomeRegion)
	}
	if len(got.AllowedRegions) != 2 || got.AllowedRegions[0] != "eu-west-1" || got.AllowedRegions[1] != "eu-central-1" {
		t.Errorf("AllowedRegions=%v", got.AllowedRegions)
	}
	// Mutating the caller's slice must not reach the stored tenant.
	want.AllowedRegions[0] = "us-east-1"
	again, _ := s.GetTenant(ctx, "t1")
	if again.AllowedRegions[0] != "eu-west-1" {
		t.Errorf("stored tenant aliased caller slice: %v", again.AllowedRegions)
	}
}

func TestPutGetTenant_EnforceWritesRoundtrip(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	if err := s.PutTenant(ctx, &tenant.Tenant{
		ID: "t1", Slug: "acme", HomeRegion: "eu-west-1", EnforceWrites: true,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.EnforceWrites {
		t.Error("EnforceWrites did not round-trip true")
	}
	// And the zero value (false) round-trips too — the fail-open default.
	if err := s.PutTenant(ctx, &tenant.Tenant{ID: "t2", Slug: "beta"}); err != nil {
		t.Fatalf("Put t2: %v", err)
	}
	got2, _ := s.GetTenant(ctx, "t2")
	if got2.EnforceWrites {
		t.Error("EnforceWrites zero value not false")
	}
}

func TestPutGetTenant_RegionFieldsZeroIsUnconstrained(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	if err := s.PutTenant(ctx, mkTenant("t1", "acme")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, _ := s.GetTenant(ctx, "t1")
	if got.HomeRegion != "" || got.AllowedRegions != nil {
		t.Errorf("region fields not zero-valued: home=%q allowed=%v", got.HomeRegion, got.AllowedRegions)
	}
}

func TestGetTenant_MissingIsErrTenantNotFound(t *testing.T) {
	t.Parallel()
	s := memory.New()
	if _, err := s.GetTenant(context.Background(), "ghost"); !errors.Is(err, tenant.ErrTenantNotFound) {
		t.Errorf("err=%v", err)
	}
}

func TestPutTenant_RejectsInvalid(t *testing.T) {
	t.Parallel()
	s := memory.New()
	if err := s.PutTenant(context.Background(), &tenant.Tenant{Slug: "x"}); !errors.Is(err, tenant.ErrInvalidTenant) {
		t.Errorf("err=%v", err)
	}
}

func TestPutTenant_PreservesCreatedAt(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	first, _ := s.GetTenant(ctx, "t1")
	_ = s.PutTenant(ctx, mkTenant("t1", "acme-renamed"))
	second, _ := s.GetTenant(ctx, "t1")
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("CreatedAt drifted on update: %v vs %v", first.CreatedAt, second.CreatedAt)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) && !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Errorf("UpdatedAt regressed")
	}
}

func TestListTenants_SortedByID(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	for _, id := range []string{"t-c", "t-a", "t-b"} {
		_ = s.PutTenant(ctx, mkTenant(id, id))
	}
	out, _ := s.ListTenants(ctx)
	if len(out) != 3 || out[0].ID != "t-a" || out[2].ID != "t-c" {
		t.Errorf("List=%+v", out)
	}
}

func TestDeleteTenant_CascadesDomains(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutDomain(ctx, mkDomain("acme.com", "t1"))
	_ = s.DeleteTenant(ctx, "t1")
	if _, err := s.GetDomain(ctx, "acme.com"); !errors.Is(err, tenant.ErrDomainNotFound) {
		t.Errorf("orphan domain survived: %v", err)
	}
}

func TestPutDomain_RoundtripWithCaseInsensitiveLookup(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutDomain(ctx, mkDomain("Acme.COM", "t1"))
	got, err := s.GetDomain(ctx, "acme.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Hostname != "acme.com" {
		t.Errorf("hostname not normalized: %q", got.Hostname)
	}
}

func TestGetDomain_TrailingDotNormalised(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutDomain(ctx, mkDomain("acme.com.", "t1"))
	if _, err := s.GetDomain(ctx, "acme.com"); err != nil {
		t.Errorf("trailing-dot normalization failed: %v", err)
	}
}

func TestPutDomain_RejectsUnknownTenant(t *testing.T) {
	t.Parallel()
	s := memory.New()
	if err := s.PutDomain(context.Background(), mkDomain("acme.com", "ghost")); !errors.Is(err, tenant.ErrTenantNotFound) {
		t.Errorf("err=%v", err)
	}
}

func TestPutDomain_HostnameConflictRejected(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutTenant(ctx, mkTenant("t2", "beta"))
	_ = s.PutDomain(ctx, mkDomain("shared.com", "t1"))
	if err := s.PutDomain(ctx, mkDomain("shared.com", "t2")); !errors.Is(err, tenant.ErrDomainExists) {
		t.Errorf("err=%v, want ErrDomainExists", err)
	}
}

func TestPutDomain_SameTenantUpdateAllowed(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutDomain(ctx, mkDomain("acme.com", "t1"))
	d := mkDomain("acme.com", "t1")
	d.IsApex = true
	if err := s.PutDomain(ctx, d); err != nil {
		t.Errorf("re-put: %v", err)
	}
	got, _ := s.GetDomain(ctx, "acme.com")
	if !got.IsApex {
		t.Error("update did not take effect")
	}
}

func TestListDomainsByTenant(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutTenant(ctx, mkTenant("t2", "beta"))
	_ = s.PutDomain(ctx, mkDomain("acme.com", "t1"))
	_ = s.PutDomain(ctx, mkDomain("portal.acme.com", "t1"))
	_ = s.PutDomain(ctx, mkDomain("beta.io", "t2"))

	out, _ := s.ListDomainsByTenant(ctx, "t1")
	if len(out) != 2 {
		t.Errorf("len=%d, want 2: %+v", len(out), out)
	}
}

func TestDeleteDomain_Idempotent(t *testing.T) {
	t.Parallel()
	s := memory.New()
	if err := s.DeleteDomain(context.Background(), "ghost.com"); err != nil {
		t.Errorf("delete on empty: %v", err)
	}
}

func TestConcurrentAccess_NoRace(t *testing.T) {
	t.Parallel()
	// Race detector catches mutation-during-read; this just exercises
	// the path concurrently.
	s := memory.New()
	ctx := context.Background()
	_ = s.PutTenant(ctx, mkTenant("t1", "acme"))
	_ = s.PutDomain(ctx, mkDomain("acme.com", "t1"))

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = s.GetDomain(ctx, "acme.com")
		}()
		go func(i int) {
			defer wg.Done()
			host := "h" + string(rune('a'+(i%10))) + ".com"
			_ = s.PutDomain(ctx, mkDomain(host, "t1"))
		}(i)
	}
	wg.Wait()
}
