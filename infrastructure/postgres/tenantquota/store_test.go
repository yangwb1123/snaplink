package tenantquota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/test/testkit/tenantquotatest"
)

func TestSchemaDeclaresAtomicQuotaBoundaries(t *testing.T) {
	required := []string{
		"tenant_id TEXT PRIMARY KEY",
		"CHECK (max_clients >= 0)",
		"clients_limited BOOLEAN",
		"clients_generation BIGINT",
		"tenant_quota_resource_leases",
		"CHECK (quantity > 0)",
		"PRIMARY KEY (tenant_id, window_second)",
		"idx_tenant_quota_token_windows_expiry",
	}
	for _, fragment := range required {
		if !strings.Contains(schema, fragment) {
			t.Errorf("tenant quota migration missing %q", fragment)
		}
	}
	if MaxVersion() != 2 {
		t.Fatalf("MaxVersion() = %d, want 2", MaxVersion())
	}
}

func TestPostgresTenantQuotaStore_Conformance(t *testing.T) {
	store := integrationStore(t)
	tenantquotatest.ConformanceSuite{Factory: func(t *testing.T) core.TenantQuotaStore {
		truncateTenantQuota(t, store.db)
		return newWithClock(store.db, time.Now)
	}}.Run(t)
}

func TestNewWithDBMigrationIsIdempotent(t *testing.T) {
	store := integrationStore(t)
	second, err := NewWithDB(store.db, testDialect())
	if err != nil {
		t.Fatalf("second NewWithDB: %v", err)
	}
	if second.DB() != store.DB() {
		t.Fatal("NewWithDB did not preserve the shared pool")
	}
}

func TestPostgresTenantQuotaStore_MultiReplicaHardLimits(t *testing.T) {
	dsn := integrationDSN(t)
	stores := replicaStores(t, dsn, 4)
	truncateTenantQuota(t, stores[0].db)
	ctx := context.Background()
	if err := stores[0].SetQuota(ctx, "tenant-replicas-gauge", &core.TenantQuota{MaxClients: 7}); err != nil {
		t.Fatal(err)
	}
	accepted := concurrentIncrements(t, stores, "tenant-replicas-gauge", core.ResourceClients, 1, 64)
	if accepted != 7 {
		t.Fatalf("gauge accepted = %d, want 7", accepted)
	}
	usage, err := stores[1].GetUsage(ctx, "tenant-replicas-gauge")
	if err != nil || usage.Clients != 7 {
		t.Fatalf("cross-replica gauge usage = %+v, %v", usage, err)
	}
	if err := stores[0].SetQuota(ctx, "tenant-replicas-rate", &core.TenantQuota{MaxTokenRate: 2}); err != nil {
		t.Fatal(err)
	}
	accepted = concurrentIncrements(t, stores, "tenant-replicas-rate", core.ResourceTokenRate, 3, 80)
	if accepted != 40 {
		t.Fatalf("token increments accepted = %d, want 40", accepted)
	}
	usage, err = stores[2].GetUsage(ctx, "tenant-replicas-rate")
	if err != nil || usage.TokenRate != 2 {
		t.Fatalf("cross-replica token rate = %+v, %v", usage, err)
	}
}

func TestPostgresTenantQuotaStore_MultiReplicaLeasesAndCAS(t *testing.T) {
	dsn := integrationDSN(t)
	stores := replicaStores(t, dsn, 4)
	truncateTenantQuota(t, stores[0].db)
	ctx := context.Background()
	if err := stores[0].SetQuota(ctx, "tenant-replica-leases", &core.TenantQuota{MaxClients: 5}); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 32)
	var wait sync.WaitGroup
	for index := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := stores[index%len(stores)].ReserveResource(
				ctx, "tenant-replica-leases", core.ResourceClients, fmt.Sprintf("client-%d", index),
			)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, core.ErrQuotaExceeded) {
			t.Fatalf("multi-replica reserve: %v", err)
		}
	}
	if accepted != 5 {
		t.Fatalf("multi-replica leases accepted = %d, want 5", accepted)
	}
	before, err := stores[0].GetResourceUsage(ctx, "tenant-replica-leases", core.ResourceClients)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stores[1].ReleaseResource(ctx, "tenant-replica-leases", core.ResourceClients, "client-0"); err != nil {
		t.Fatal(err)
	}
	if generation, err := stores[2].ReconcileUsage(ctx, "tenant-replica-leases", core.ResourceClients, 9, before.Generation); !errors.Is(err, core.ErrQuotaRevisionConflict) || generation != before.Generation+1 {
		t.Fatalf("stale cross-replica reconcile generation=%d err=%v", generation, err)
	}
}

func concurrentIncrements(
	t *testing.T, stores []*Store, tenantID string, resource core.ResourceType, delta int64, count int,
) int {
	t.Helper()
	results := make(chan error, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- stores[index%len(stores)].IncrementUsage(context.Background(), tenantID, resource, delta)
		}()
	}
	wait.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, core.ErrQuotaExceeded) {
			t.Fatalf("concurrent increment: %v", err)
		}
	}
	return accepted
}

func integrationStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("pgx", integrationDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewWithDB(db, testDialect())
	if err != nil {
		t.Fatal(err)
	}
	truncateTenantQuota(t, db)
	return store
}

func replicaStores(t *testing.T, dsn string, count int) []*Store {
	t.Helper()
	stores := make([]*Store, 0, count)
	for index := range count {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		store, err := NewWithDB(db, testDialect())
		if err != nil {
			t.Fatalf("replica %d: %v", index, err)
		}
		stores = append(stores, store)
	}
	return stores
}

func truncateTenantQuota(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `TRUNCATE
tenant_quota_token_windows, tenant_quota_state CASCADE`)
	if err != nil {
		t.Fatalf("truncate tenant quota tables: %v", err)
	}
}

func integrationDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set; skipping tenant quota integration test")
	}
	return dsn
}

func testDialect() postgresbackend.Dialect {
	return postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT"))
}

func ExampleStore() {
	var db *sql.DB
	store, err := NewWithDB(db, postgresbackend.DialectPostgres)
	fmt.Println(store, err != nil)
	// Output: <nil> true
}
