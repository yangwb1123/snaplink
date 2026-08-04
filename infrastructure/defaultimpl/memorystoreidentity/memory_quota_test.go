package memorystoreidentity

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/test/testkit/tenantquotatest"
)

func TestMemoryTenantQuotaStore_Conformance(t *testing.T) {
	tenantquotatest.ConformanceSuite{Factory: func(*testing.T) core.TenantQuotaStore {
		return NewMemoryTenantQuotaStore()
	}}.Run(t)
}

func TestMemoryTenantQuotaStore_TokenWindowExpiresMonotonically(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	s := newMemoryTenantQuotaStore(func() time.Time { return now })
	_ = s.SetQuota(ctx, "t1", &core.TenantQuota{MaxTokenRate: 1})
	if err := s.IncrementUsage(ctx, "t1", core.ResourceTokenRate, 60); err != nil {
		t.Fatal(err)
	}
	now = now.Add(60 * time.Second)
	usage, err := s.GetUsage(ctx, "t1")
	if err != nil || usage.TokenRate != 0 {
		t.Fatalf("expired token rate = %v, %v", usage.TokenRate, err)
	}
	now = now.Add(-2 * time.Minute)
	if err := s.IncrementUsage(ctx, "t1", core.ResourceTokenRate, 60); err != nil {
		t.Fatalf("backward clock increment: %v", err)
	}
}
