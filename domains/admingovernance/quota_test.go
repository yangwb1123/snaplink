package admingovernance

import (
	"context"
	"testing"
	"time"
)

func TestMemoryWriteQuotaStore_ConsumeWithinLimit(t *testing.T) {
	store := NewMemoryWriteQuotaStore()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		res, err := store.Consume(ctx, "admin:a", 3, time.Hour, now)
		if err != nil {
			t.Fatalf("Consume[%d]: %v", i, err)
		}
		if !res.Allowed {
			t.Fatalf("Consume[%d].Allowed = false; want true (limit not yet reached)", i)
		}
	}
	// 4th call exceeds the limit of 3.
	res, err := store.Consume(ctx, "admin:a", 3, time.Hour, now)
	if err != nil {
		t.Fatalf("Consume overflow: %v", err)
	}
	if res.Allowed {
		t.Fatal("4th Consume.Allowed = true; want false (quota exhausted)")
	}
	if res.Remaining != 0 {
		t.Errorf("Remaining = %d; want 0", res.Remaining)
	}
}

func TestMemoryWriteQuotaStore_WindowResets(t *testing.T) {
	store := NewMemoryWriteQuotaStore()
	ctx := context.Background()
	window := time.Hour
	t0 := time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC)

	for i := 0; i < 2; i++ {
		if res, _ := store.Consume(ctx, "admin:a", 2, window, t0); !res.Allowed {
			t.Fatalf("Consume[%d] at t0 should be allowed", i)
		}
	}
	if res, _ := store.Consume(ctx, "admin:a", 2, window, t0); res.Allowed {
		t.Fatal("3rd consume at t0 should be blocked")
	}

	// Advance past the window boundary — budget must reset.
	t1 := t0.Add(window)
	res, err := store.Consume(ctx, "admin:a", 2, window, t1)
	if err != nil {
		t.Fatalf("Consume after window roll: %v", err)
	}
	if !res.Allowed {
		t.Fatal("Consume after window roll should be allowed (fresh window)")
	}
}

func TestMemoryWriteQuotaStore_KeysAreIndependent(t *testing.T) {
	store := NewMemoryWriteQuotaStore()
	ctx := context.Background()
	now := time.Now()

	for i := 0; i < 2; i++ {
		if res, _ := store.Consume(ctx, "admin:a", 2, time.Hour, now); !res.Allowed {
			t.Fatalf("admin:a[%d] should be allowed", i)
		}
	}
	if res, _ := store.Consume(ctx, "admin:a", 2, time.Hour, now); res.Allowed {
		t.Fatal("admin:a should now be exhausted")
	}
	// A different key must have its own independent budget.
	if res, _ := store.Consume(ctx, "admin:b", 2, time.Hour, now); !res.Allowed {
		t.Fatal("admin:b should be unaffected by admin:a's quota")
	}
}

func TestMemoryWriteQuotaStore_UnlimitedWhenNotConfigured(t *testing.T) {
	store := NewMemoryWriteQuotaStore()
	ctx := context.Background()
	now := time.Now()
	for i := 0; i < 100; i++ {
		if res, _ := store.Consume(ctx, "admin:a", 0, 0, now); !res.Allowed {
			t.Fatalf("iteration %d: limit<=0 must always allow", i)
		}
	}
}

func TestQuotaKey(t *testing.T) {
	tests := []struct {
		keyBy, actorID, tenantHint, want string
	}{
		{"", "admin1", "", "admin:admin1"},
		{"admin", "admin1", "tenant1", "admin:admin1"},
		{"tenant", "admin1", "tenant1", "tenant:tenant1"},
		{"tenant", "admin1", "", "admin:admin1"}, // fallback: no tenant hint
	}
	for _, tt := range tests {
		if got := QuotaKey(tt.keyBy, tt.actorID, tt.tenantHint); got != tt.want {
			t.Errorf("QuotaKey(%q,%q,%q) = %q; want %q", tt.keyBy, tt.actorID, tt.tenantHint, got, tt.want)
		}
	}
}
