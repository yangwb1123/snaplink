// Package tenantquotatest defines the shared behavioral contract for every
// core.TenantQuotaStore implementation.
package tenantquotatest

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// ConformanceSuite runs quota semantics against a fresh store per subtest.
type ConformanceSuite struct {
	Factory func(*testing.T) core.TenantQuotaStore
}

// Run executes the common quota-store contract.
func (s ConformanceSuite) Run(t *testing.T) {
	t.Helper()
	if s.Factory == nil {
		t.Fatal("ConformanceSuite: Factory required")
	}
	cases := []struct {
		name string
		run  func(*testing.T, core.TenantQuotaStore)
	}{
		{"DefaultUnlimited", testDefaultUnlimited},
		{"QuotaValuesAreIsolated", testQuotaValuesAreIsolated},
		{"UsageValuesAreIsolated", testUsageValuesAreIsolated},
		{"GaugeLimitsAndFloor", testGaugeLimitsAndFloor},
		{"InvalidIdentityAndResource", testInvalidIdentityAndResource},
		{"InvalidDeltaAndQuota", testInvalidDeltaAndQuota},
		{"TokenRateWindow", testTokenRateWindow},
		{"ConcurrentHardLimit", testConcurrentHardLimit},
		{"ExplicitHardZero", testExplicitHardZero},
		{"IdempotentResourceLease", testIdempotentResourceLease},
		{"ConcurrentSameResourceLease", testConcurrentSameResourceLease},
		{"GenerationCASReconcile", testGenerationCASReconcile},
		{"ExactResourceSetReconcile", testExactResourceSetReconcile},
		{"MonotonicQuotaProjection", testMonotonicQuotaProjection},
		{"ResetAllUsage", testResetAllUsage},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.run(t, s.Factory(t))
		})
	}
}

func testDefaultUnlimited(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	quota, err := store.GetQuota(ctx, "tenant-default")
	if err != nil || *quota != (core.TenantQuota{}) {
		t.Fatalf("default quota = %+v, %v", quota, err)
	}
	for _, resource := range gaugeResources() {
		if err := store.IncrementUsage(ctx, "tenant-default", resource, 3); err != nil {
			t.Fatalf("unlimited %s increment: %v", resource, err)
		}
	}
	usage, err := store.GetUsage(ctx, "tenant-default")
	if err != nil || usage.Clients != 3 || usage.Users != 3 || usage.Sessions != 3 {
		t.Fatalf("default usage = %+v, %v", usage, err)
	}
}

func testQuotaValuesAreIsolated(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	input := &core.TenantQuota{MaxClients: 1, MaxUsers: 2, MaxSessions: 3, MaxTokenRate: 4}
	if err := store.SetQuota(ctx, "tenant-alias", input); err != nil {
		t.Fatal(err)
	}
	input.MaxClients = 99
	first, err := store.GetQuota(ctx, "tenant-alias")
	if err != nil || first.MaxClients != 1 {
		t.Fatalf("quota after input mutation = %+v, %v", first, err)
	}
	first.MaxUsers = 99
	second, err := store.GetQuota(ctx, "tenant-alias")
	if err != nil || second.MaxUsers != 2 {
		t.Fatalf("quota after result mutation = %+v, %v", second, err)
	}
}

func testUsageValuesAreIsolated(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	if err := store.IncrementUsage(ctx, "tenant-usage-alias", core.ResourceUsers, 1); err != nil {
		t.Fatal(err)
	}
	first, err := store.GetUsage(ctx, "tenant-usage-alias")
	if err != nil {
		t.Fatal(err)
	}
	first.Users = 99
	second, err := store.GetUsage(ctx, "tenant-usage-alias")
	if err != nil || second.Users != 1 {
		t.Fatalf("usage after result mutation = %+v, %v", second, err)
	}
}

func testGaugeLimitsAndFloor(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	quota := &core.TenantQuota{MaxClients: 2, MaxUsers: 2, MaxSessions: 2}
	if err := store.SetQuota(ctx, "tenant-gauges", quota); err != nil {
		t.Fatal(err)
	}
	for _, resource := range gaugeResources() {
		if err := store.IncrementUsage(ctx, "tenant-gauges", resource, 2); err != nil {
			t.Fatalf("fill %s: %v", resource, err)
		}
		if err := store.IncrementUsage(ctx, "tenant-gauges", resource, 1); !errors.Is(err, core.ErrQuotaExceeded) {
			t.Fatalf("overfill %s = %v", resource, err)
		}
		if err := store.DecrementUsage(ctx, "tenant-gauges", resource, 3); err != nil {
			t.Fatalf("floor %s: %v", resource, err)
		}
	}
	usage, err := store.GetUsage(ctx, "tenant-gauges")
	if err != nil || usage.Clients != 0 || usage.Users != 0 || usage.Sessions != 0 {
		t.Fatalf("floored usage = %+v, %v", usage, err)
	}
}

func testInvalidIdentityAndResource(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	for _, tenantID := range []string{"", " tenant", "tenant "} {
		_, err := store.GetQuota(ctx, tenantID)
		assertInvalid(t, "GetQuota tenant", err)
		_, err = store.GetUsage(ctx, tenantID)
		assertInvalid(t, "GetUsage tenant", err)
		assertInvalid(t, "ResetUsage tenant", store.ResetUsage(ctx, tenantID))
	}
	unknown := core.ResourceType("unknown")
	assertInvalid(t, "increment resource", store.IncrementUsage(ctx, "tenant-invalid", unknown, 1))
	assertInvalid(t, "decrement resource", store.DecrementUsage(ctx, "tenant-invalid", unknown, 1))
}

func testInvalidDeltaAndQuota(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	for _, delta := range []int64{-1, 0} {
		assertInvalid(t, "increment delta", store.IncrementUsage(ctx, "tenant-invalid", core.ResourceClients, delta))
		assertInvalid(t, "decrement delta", store.DecrementUsage(ctx, "tenant-invalid", core.ResourceClients, delta))
	}
	assertInvalid(t, "nil quota", store.SetQuota(ctx, "tenant-invalid", nil))
	assertInvalid(t, "negative quota", store.SetQuota(ctx, "tenant-invalid", &core.TenantQuota{MaxUsers: -1}))
	tooFast := int64(math.MaxInt64/core.TenantQuotaTokenWindowSeconds) + 1
	if tooFast <= int64(math.MaxInt) {
		assertInvalid(t, "overflowing rate", store.SetQuota(ctx, "tenant-invalid", &core.TenantQuota{MaxTokenRate: int(tooFast)}))
	}
}

func testTokenRateWindow(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	if err := store.SetQuota(ctx, "tenant-rate", &core.TenantQuota{MaxTokenRate: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.IncrementUsage(ctx, "tenant-rate", core.ResourceTokenRate, 60); err != nil {
		t.Fatalf("fill token window: %v", err)
	}
	assertTokenRate(t, store, 1)
	if err := store.IncrementUsage(ctx, "tenant-rate", core.ResourceTokenRate, 1); !errors.Is(err, core.ErrQuotaExceeded) {
		t.Fatalf("overfill token window = %v", err)
	}
	if err := store.DecrementUsage(ctx, "tenant-rate", core.ResourceTokenRate, 10); err != nil {
		t.Fatal(err)
	}
	assertTokenRate(t, store, float64(50)/60)
	cleaner, ok := store.(core.TenantQuotaWindowCleaner)
	if !ok {
		t.Fatal("store does not implement TenantQuotaWindowCleaner")
	}
	removed, err := cleaner.CleanupTokenRateWindows(ctx, time.Now().Add(2*time.Minute))
	if err != nil || removed < 1 {
		t.Fatalf("cleanup = %d, %v", removed, err)
	}
	assertTokenRate(t, store, 0)
}

func testConcurrentHardLimit(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	if err := store.SetQuota(ctx, "tenant-concurrent", &core.TenantQuota{MaxClients: 5}); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 32)
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- store.IncrementUsage(ctx, "tenant-concurrent", core.ResourceClients, 1)
		}()
	}
	wait.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, core.ErrQuotaExceeded) {
			t.Fatalf("concurrent increment = %v", err)
		}
	}
	if accepted != 5 {
		t.Fatalf("accepted = %d, want 5", accepted)
	}
}

func testExplicitHardZero(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	quota := &core.TenantQuota{
		ClientsLimited: true, UsersLimited: true, SessionsLimited: true, TokenRateLimited: true,
	}
	if err := store.SetQuota(ctx, "tenant-hard-zero", quota); err != nil {
		t.Fatal(err)
	}
	for _, resource := range append(gaugeResources(), core.ResourceTokenRate) {
		if err := store.IncrementUsage(ctx, "tenant-hard-zero", resource, 1); !errors.Is(err, core.ErrQuotaExceeded) {
			t.Fatalf("hard-zero %s increment = %v", resource, err)
		}
	}
}

func testIdempotentResourceLease(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	resources := requireResourceStore(t, store)
	if err := store.SetQuota(ctx, "tenant-lease", &core.TenantQuota{MaxClients: 1}); err != nil {
		t.Fatal(err)
	}
	reserved, err := resources.ReserveResource(ctx, "tenant-lease", core.ResourceClients, "client-1")
	if err != nil || !reserved {
		t.Fatalf("first reserve = %t, %v", reserved, err)
	}
	reserved, err = resources.ReserveResource(ctx, "tenant-lease", core.ResourceClients, "client-1")
	if err != nil || reserved {
		t.Fatalf("replayed reserve = %t, %v", reserved, err)
	}
	if _, err := resources.ReserveResource(ctx, "tenant-lease", core.ResourceClients, "client-2"); !errors.Is(err, core.ErrQuotaExceeded) {
		t.Fatalf("over-limit reserve = %v", err)
	}
	released, err := resources.ReleaseResource(ctx, "tenant-lease", core.ResourceClients, "client-1")
	if err != nil || !released {
		t.Fatalf("first release = %t, %v", released, err)
	}
	released, err = resources.ReleaseResource(ctx, "tenant-lease", core.ResourceClients, "client-1")
	if err != nil || released {
		t.Fatalf("replayed release = %t, %v", released, err)
	}
	if reserved, err = resources.ReserveResource(ctx, "tenant-lease", core.ResourceClients, "client-2"); err != nil || !reserved {
		t.Fatalf("reserve after release = %t, %v", reserved, err)
	}
}

func testConcurrentSameResourceLease(t *testing.T, store core.TenantQuotaStore) {
	resources := requireResourceStore(t, store)
	results := make(chan bool, 32)
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			reserved, err := resources.ReserveResource(context.Background(), "tenant-same-lease", core.ResourceUsers, "user-1")
			if err != nil {
				t.Errorf("concurrent reserve: %v", err)
			}
			results <- reserved
		}()
	}
	wait.Wait()
	close(results)
	reservedCount := 0
	for reserved := range results {
		if reserved {
			reservedCount++
		}
	}
	usage, err := store.GetUsage(context.Background(), "tenant-same-lease")
	if err != nil || reservedCount != 1 || usage.Users != 1 {
		t.Fatalf("same lease reserved=%d usage=%+v err=%v", reservedCount, usage, err)
	}
}

func testGenerationCASReconcile(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	resources := requireResourceStore(t, store)
	initial, err := resources.GetResourceUsage(ctx, "tenant-cas", core.ResourceSessions)
	if err != nil || initial.Generation != 0 {
		t.Fatalf("initial resource usage = %+v, %v", initial, err)
	}
	if err := store.IncrementUsage(ctx, "tenant-cas", core.ResourceSessions, 1); err != nil {
		t.Fatal(err)
	}
	current, err := resources.ReconcileUsage(ctx, "tenant-cas", core.ResourceSessions, 7, initial.Generation)
	if !errors.Is(err, core.ErrQuotaRevisionConflict) || current != 1 {
		t.Fatalf("stale reconcile generation=%d err=%v", current, err)
	}
	next, err := resources.ReconcileUsage(ctx, "tenant-cas", core.ResourceSessions, 7, current)
	if err != nil || next != 2 {
		t.Fatalf("successful reconcile generation=%d err=%v", next, err)
	}
	if _, err := resources.ReleaseResource(ctx, "tenant-cas", core.ResourceSessions, "legacy-session"); err != nil {
		t.Fatal(err)
	}
	if _, err := resources.ReleaseResource(ctx, "tenant-cas", core.ResourceSessions, "legacy-session"); err != nil {
		t.Fatal(err)
	}
	usage, err := resources.GetResourceUsage(ctx, "tenant-cas", core.ResourceSessions)
	if err != nil || usage.Value != 6 || usage.Generation != 3 {
		t.Fatalf("reconciled usage = %+v, %v", usage, err)
	}
}

func testExactResourceSetReconcile(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	resources := requireResourceSetStore(t, store)
	if err := store.SetQuota(ctx, "tenant-resource-set", &core.TenantQuota{MaxSessions: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := resources.ReserveResource(ctx, "tenant-resource-set", core.ResourceSessions, "session-old"); err != nil {
		t.Fatal(err)
	}
	before, err := resources.GetResourceUsage(ctx, "tenant-resource-set", core.ResourceSessions)
	if err != nil {
		t.Fatal(err)
	}
	next, err := resources.ReconcileResourceSet(ctx, "tenant-resource-set", core.ResourceSessions,
		[]string{"session-live", "session-new"}, before.Generation)
	if err != nil || next != before.Generation+1 {
		t.Fatalf("exact reconcile generation=%d err=%v", next, err)
	}
	for id, want := range map[string]bool{
		"session-old": false, "session-live": true, "session-new": true,
	} {
		active, err := resources.ResourceLeaseActive(ctx, "tenant-resource-set", core.ResourceSessions, id)
		if err != nil || active != want {
			t.Fatalf("lease %s active=%t err=%v, want %t", id, active, err, want)
		}
	}
	if released, err := resources.ReleaseResource(ctx, "tenant-resource-set", core.ResourceSessions, "session-old"); err != nil || released {
		t.Fatalf("late tombstoned release=%t err=%v", released, err)
	}
	usage, err := store.GetUsage(ctx, "tenant-resource-set")
	if err != nil || usage.Sessions != 2 {
		t.Fatalf("exact usage=%+v err=%v, want sessions=2", usage, err)
	}
	if _, err := resources.ReconcileResourceSet(ctx, "tenant-resource-set", core.ResourceSessions,
		[]string{"session-live"}, before.Generation); !errors.Is(err, core.ErrQuotaRevisionConflict) {
		t.Fatalf("stale exact reconcile = %v", err)
	}
	if _, err := resources.ReconcileResourceSet(ctx, "tenant-resource-set", core.ResourceSessions,
		[]string{"duplicate", "duplicate"}, next); !errors.Is(err, core.ErrInvalidQuotaOperation) {
		t.Fatalf("duplicate exact set = %v", err)
	}
}

func testMonotonicQuotaProjection(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	projections := requireProjectionStore(t, store)
	projection := &core.TenantQuotaProjection{
		Revision: 2, Quota: core.TenantQuota{ClientsLimited: true},
	}
	applied, err := projections.ApplyQuotaProjection(ctx, "tenant-projection", projection)
	if err != nil || !applied {
		t.Fatalf("apply projection = %t, %v", applied, err)
	}
	got, err := projections.GetQuotaProjection(ctx, "tenant-projection")
	if err != nil || *got != *projection {
		t.Fatalf("projection = %+v, %v", got, err)
	}
	stale := &core.TenantQuotaProjection{Revision: 1, Quota: core.TenantQuota{MaxClients: 99}}
	if applied, err = projections.ApplyQuotaProjection(ctx, "tenant-projection", stale); err != nil || applied {
		t.Fatalf("stale projection = %t, %v", applied, err)
	}
	equivocation := &core.TenantQuotaProjection{Revision: 2, Quota: core.TenantQuota{MaxClients: 1}}
	if _, err := projections.ApplyQuotaProjection(ctx, "tenant-projection", equivocation); !errors.Is(err, core.ErrQuotaRevisionConflict) {
		t.Fatalf("same-revision equivocation = %v", err)
	}
	if err := store.SetQuota(ctx, "tenant-projection", &core.TenantQuota{MaxClients: 9}); !errors.Is(err, core.ErrQuotaRevisionConflict) {
		t.Fatalf("unversioned overwrite = %v", err)
	}
	if err := store.IncrementUsage(ctx, "tenant-projection", core.ResourceClients, 1); !errors.Is(err, core.ErrQuotaExceeded) {
		t.Fatalf("projected hard-zero increment = %v", err)
	}
}

func testResetAllUsage(t *testing.T, store core.TenantQuotaStore) {
	ctx := context.Background()
	for _, resource := range append(gaugeResources(), core.ResourceTokenRate) {
		if err := store.IncrementUsage(ctx, "tenant-reset", resource, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ResetUsage(ctx, "tenant-reset"); err != nil {
		t.Fatal(err)
	}
	usage, err := store.GetUsage(ctx, "tenant-reset")
	if err != nil || *usage != (core.TenantUsage{}) {
		t.Fatalf("reset usage = %+v, %v", usage, err)
	}
}

func assertTokenRate(t *testing.T, store core.TenantQuotaStore, want float64) {
	t.Helper()
	usage, err := store.GetUsage(context.Background(), "tenant-rate")
	if err != nil || math.Abs(usage.TokenRate-want) > 0.000001 {
		t.Fatalf("token rate = %v, %v; want %v", usage.TokenRate, err, want)
	}
}

func assertInvalid(t *testing.T, operation string, err error) {
	t.Helper()
	if !errors.Is(err, core.ErrInvalidQuotaOperation) {
		t.Fatalf("%s = %v, want ErrInvalidQuotaOperation", operation, err)
	}
}

func gaugeResources() []core.ResourceType {
	return []core.ResourceType{core.ResourceClients, core.ResourceUsers, core.ResourceSessions}
}

func requireResourceStore(t *testing.T, store core.TenantQuotaStore) core.TenantQuotaResourceStore {
	t.Helper()
	resources, ok := store.(core.TenantQuotaResourceStore)
	if !ok {
		t.Fatal("store does not implement TenantQuotaResourceStore")
	}
	return resources
}

func requireResourceSetStore(t *testing.T, store core.TenantQuotaStore) core.TenantQuotaResourceSetStore {
	t.Helper()
	resources, ok := store.(core.TenantQuotaResourceSetStore)
	if !ok {
		t.Fatal("store does not implement TenantQuotaResourceSetStore")
	}
	return resources
}

func requireProjectionStore(t *testing.T, store core.TenantQuotaStore) core.TenantQuotaProjectionStore {
	t.Helper()
	projections, ok := store.(core.TenantQuotaProjectionStore)
	if !ok {
		t.Fatal("store does not implement TenantQuotaProjectionStore")
	}
	return projections
}
