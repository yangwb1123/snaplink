package memorystoreidentity

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestMemoryInvitationStoreSweepStrictBoundary(t *testing.T) {
	now := time.Now()
	store := NewMemoryInvitationStore()
	store.invts["expired"] = &core.Invitation{Token: "expired", ExpiresAt: now.Add(-time.Nanosecond)}
	store.invts["zero"] = &core.Invitation{Token: "zero"}
	store.invts["boundary"] = &core.Invitation{Token: "boundary", ExpiresAt: now}
	store.invts["live"] = &core.Invitation{Token: "live", ExpiresAt: now.Add(time.Nanosecond)}
	store.lastSweep.Store(0)

	store.sweepExpired(now)

	for _, token := range []string{"expired", "zero"} {
		if _, ok := store.invts[token]; ok {
			t.Errorf("expired invitation %q remains", token)
		}
	}
	for _, token := range []string{"boundary", "live"} {
		if _, ok := store.invts[token]; !ok {
			t.Errorf("invitation %q was swept", token)
		}
	}
}

func TestMemoryInvitationStoreIssueSweepsExpired(t *testing.T) {
	store := NewMemoryInvitationStore()
	store.invts["expired"] = &core.Invitation{
		Token: "expired", TenantID: "tenant", ExpiresAt: time.Now().Add(-time.Hour),
	}
	store.lastSweep.Store(0)
	if err := store.Issue(context.Background(), &core.Invitation{
		Token: "live", TenantID: "tenant", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, ok := store.invts["expired"]; ok {
		t.Error("expired invitation remains after Issue sweep")
	}
	if _, ok := store.invts["live"]; !ok {
		t.Error("new invitation was not stored")
	}
	listed, err := store.ListByTenant(context.Background(), "tenant")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(listed) != 1 || listed[0].Token != "live" {
		t.Fatalf("ListByTenant = %#v, want only live invitation", listed)
	}
}

func TestMemoryInvitationStoreConcurrentIssueConsume(t *testing.T) {
	store := NewMemoryInvitationStore()
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				token := fmt.Sprintf("token-%d-%d", worker, i)
				if err := store.Issue(context.Background(), &core.Invitation{
					Token: token, TenantID: "tenant", Email: token,
					ExpiresAt: time.Now().Add(time.Hour),
				}); err != nil {
					t.Errorf("Issue: %v", err)
				}
				if _, err := store.Consume(context.Background(), token); err != nil {
					t.Errorf("Consume: %v", err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestMemoryInvitationStoreSweepCASGate(t *testing.T) {
	store := NewMemoryInvitationStore()
	now := time.Now()
	store.lastSweep.Store(now.UnixNano())
	store.invts["expired"] = &core.Invitation{ExpiresAt: now.Add(-time.Hour)}
	store.sweepExpired(now)
	if _, ok := store.invts["expired"]; !ok {
		t.Error("entry swept before interval elapsed")
	}
}
