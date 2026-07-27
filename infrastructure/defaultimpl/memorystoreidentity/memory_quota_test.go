package memorystoreidentity

// memory_quota_test.go is the first coverage for MemoryTenantQuotaStore. It
// characterizes the increment/rollback cap semantics the client-create and
// session-create quota gates depend on, and pins the ResourceTokenRate no-op
// that documents why the token_rate dimension is deferred (no rolling-window
// counter exists here — increment silently succeeds).

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestMemoryTenantQuotaStore_DefaultUnlimited(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryTenantQuotaStore()

	q, err := s.GetQuota(ctx, "t1")
	if err != nil {
		t.Fatalf("GetQuota: %v", err)
	}
	if q.MaxClients != 0 || q.MaxUsers != 0 || q.MaxSessions != 0 {
		t.Fatalf("unset tenant should default to unlimited, got %+v", q)
	}
	// With no quota configured every increment succeeds regardless of count.
	for i := 0; i < 5; i++ {
		if err := s.IncrementUsage(ctx, "t1", core.ResourceClients, 1); err != nil {
			t.Fatalf("increment %d under unlimited quota: %v", i, err)
		}
	}
	u, _ := s.GetUsage(ctx, "t1")
	if u.Clients != 5 {
		t.Fatalf("usage clients = %d, want 5", u.Clients)
	}
}

func TestMemoryTenantQuotaStore_ClientsCapRollsBack(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryTenantQuotaStore()
	if err := s.SetQuota(ctx, "t1", &core.TenantQuota{MaxClients: 1}); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}

	if err := s.IncrementUsage(ctx, "t1", core.ResourceClients, 1); err != nil {
		t.Fatalf("first increment: %v", err)
	}
	// Second increment exceeds MaxClients=1 → ErrQuotaExceeded, and the counter
	// MUST be rolled back so a fail-open caller doesn't leave usage inflated.
	if err := s.IncrementUsage(ctx, "t1", core.ResourceClients, 1); err != core.ErrQuotaExceeded {
		t.Fatalf("over-cap increment err = %v, want ErrQuotaExceeded", err)
	}
	u, _ := s.GetUsage(ctx, "t1")
	if u.Clients != 1 {
		t.Fatalf("usage after rejected increment = %d, want 1 (rolled back)", u.Clients)
	}
}

func TestMemoryTenantQuotaStore_ResetClears(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryTenantQuotaStore()
	_ = s.SetQuota(ctx, "t1", &core.TenantQuota{MaxSessions: 2})
	_ = s.IncrementUsage(ctx, "t1", core.ResourceSessions, 1)

	if err := s.ResetUsage(ctx, "t1"); err != nil {
		t.Fatalf("ResetUsage: %v", err)
	}
	u, _ := s.GetUsage(ctx, "t1")
	if u.Sessions != 0 {
		t.Fatalf("usage after reset = %d, want 0", u.Sessions)
	}
}

// TestMemoryTenantQuotaStore_TokenRateNoOp documents the token_rate deferral:
// the store has no ResourceTokenRate case, so an increment is silently ignored
// (never enforced, never counted). Wiring token_rate would require a rolling-
// window counter that does not exist here.
func TestMemoryTenantQuotaStore_TokenRateNoOp(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryTenantQuotaStore()
	_ = s.SetQuota(ctx, "t1", &core.TenantQuota{MaxTokenRate: 1})

	if err := s.IncrementUsage(ctx, "t1", core.ResourceTokenRate, 100); err != nil {
		t.Fatalf("token_rate increment should be a silent no-op, got %v", err)
	}
	u, _ := s.GetUsage(ctx, "t1")
	if u.TokenRate != 0 {
		t.Fatalf("token_rate must remain uncounted, got %v", u.TokenRate)
	}
}
