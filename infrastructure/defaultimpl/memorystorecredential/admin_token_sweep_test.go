package memorystorecredential

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestMemoryAdminTokenStoreSweepBoundaryAndZeroExpiry(t *testing.T) {
	now := time.Now()
	store := NewMemoryAdminTokenStore()
	store.tokens["expired"] = core.AdminToken{ID: "expired", ExpiresAt: now.Add(-time.Nanosecond)}
	store.tokens["zero"] = core.AdminToken{ID: "zero"}
	store.tokens["boundary"] = core.AdminToken{ID: "boundary", ExpiresAt: now}
	store.tokens["live"] = core.AdminToken{ID: "live", ExpiresAt: now.Add(time.Nanosecond)}
	store.lastSweep.Store(0)

	store.sweepExpired(now)

	if _, ok := store.tokens["expired"]; ok {
		t.Error("expired admin token remains")
	}
	for _, id := range []string{"zero", "boundary", "live"} {
		if _, ok := store.tokens[id]; !ok {
			t.Errorf("admin token %q was swept", id)
		}
	}
}

func TestMemoryAdminTokenStoreRecordSweepsExpired(t *testing.T) {
	store := NewMemoryAdminTokenStore()
	store.tokens["expired"] = core.AdminToken{ID: "expired", ExpiresAt: time.Now().Add(-time.Hour)}
	store.lastSweep.Store(0)
	if err := store.Record(context.Background(), core.AdminToken{ID: "live", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, ok := store.tokens["expired"]; ok {
		t.Error("expired admin token remains after Record sweep")
	}
	if _, err := store.GetByID(context.Background(), "live"); err != nil {
		t.Errorf("new admin token is not readable: %v", err)
	}
}

func TestMemoryAdminTokenStoreConcurrentRecordGetRevoke(t *testing.T) {
	store := NewMemoryAdminTokenStore()
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				id := fmt.Sprintf("token-%d-%d", worker, i)
				if err := store.Record(context.Background(), core.AdminToken{
					ID: id, ExpiresAt: time.Now().Add(time.Hour),
				}); err != nil {
					t.Errorf("Record: %v", err)
				}
				_, _ = store.GetByID(context.Background(), id)
				if err := store.Revoke(context.Background(), id); err != nil {
					t.Errorf("Revoke: %v", err)
				}
			}
		}()
	}
	wg.Wait()
}
