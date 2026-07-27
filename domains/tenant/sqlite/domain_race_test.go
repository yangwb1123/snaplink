package sqlite

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant"
)

// TestStore_PutDomainConcurrentCrossTenantClaimIsSerialized races two
// PutDomain calls claiming the SAME fresh hostname for two DIFFERENT
// tenants. Before the BEGIN IMMEDIATE fix, PutDomain ran verifyTenantExists +
// checkDomainConflict + the INSERT as three independent auto-commit
// statements: both goroutines could read the hostname as unclaimed before
// either committed its INSERT ... ON CONFLICT DO UPDATE, so the second
// writer silently overwrote the first's tenant_id — a cross-tenant domain
// hijack with NO error returned to either caller. Exactly one call must win
// the claim; the other must observe ErrDomainExists (never both nil).
func TestStore_PutDomainConcurrentCrossTenantClaimIsSerialized(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
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
