package defaultmfa

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestMemoryMFAChallengeStoreSweepOnPut(t *testing.T) {
	now := time.Now()
	store := NewMemoryMFAChallengeStore()
	store.entries["expired"] = &spi.MFAChallenge{ID: "expired", ExpiresAt: now.Add(-time.Second)}
	store.entries["live"] = &spi.MFAChallenge{ID: "live", ExpiresAt: now.Add(time.Hour)}
	store.lastSweep.Store(now.Add(-sweepInterval).UnixNano())

	if err := store.Put(context.Background(), &spi.MFAChallenge{
		ID:        "new",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := store.entries["expired"]; ok {
		t.Fatal("expired challenge was not swept on Put")
	}
	for _, id := range []string{"live", "new"} {
		if _, ok := store.entries[id]; !ok {
			t.Fatalf("live challenge %q was swept", id)
		}
	}
}

func TestMemoryMFAChallengeStoreSweepStrictBoundary(t *testing.T) {
	now := time.Now()
	store := NewMemoryMFAChallengeStore()
	store.entries["expired"] = &spi.MFAChallenge{ExpiresAt: now.Add(-time.Nanosecond)}
	store.entries["boundary"] = &spi.MFAChallenge{ExpiresAt: now}
	store.entries["live"] = &spi.MFAChallenge{ExpiresAt: now.Add(time.Nanosecond)}

	store.mu.Lock()
	sweepExpiredEntries(store.entries, now, func(entry *spi.MFAChallenge) time.Time {
		return entry.ExpiresAt
	})
	store.mu.Unlock()

	if _, ok := store.entries["expired"]; ok {
		t.Fatal("expired challenge remains after sweep")
	}
	for _, id := range []string{"boundary", "live"} {
		if _, ok := store.entries[id]; !ok {
			t.Fatalf("entry %q was swept at the strict boundary", id)
		}
	}
}

func TestMemoryPushApprovalStoreSweepOnPut(t *testing.T) {
	now := time.Now()
	store := NewMemoryPushApprovalStore()
	store.entries["expired"] = &PushApproval{ID: "expired", SubjectID: "subject", ExpiresAt: now.Add(-time.Second)}
	store.entries["live"] = &PushApproval{ID: "live", SubjectID: "subject", ExpiresAt: now.Add(time.Hour)}
	store.lastSweep.Store(now.Add(-sweepInterval).UnixNano())

	if err := store.Put(context.Background(), &PushApproval{
		ID:        "new",
		SubjectID: "subject",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := store.entries["expired"]; ok {
		t.Fatal("expired approval was not swept on Put")
	}
	for _, id := range []string{"live", "new"} {
		if _, ok := store.entries[id]; !ok {
			t.Fatalf("live approval %q was swept", id)
		}
	}
}

func TestMemoryPushApprovalStoreSweepStrictBoundary(t *testing.T) {
	now := time.Now()
	store := NewMemoryPushApprovalStore()
	store.entries["expired"] = &PushApproval{ExpiresAt: now.Add(-time.Nanosecond)}
	store.entries["boundary"] = &PushApproval{ExpiresAt: now}
	store.entries["live"] = &PushApproval{ExpiresAt: now.Add(time.Nanosecond)}

	store.mu.Lock()
	sweepExpiredEntries(store.entries, now, func(entry *PushApproval) time.Time {
		return entry.ExpiresAt
	})
	store.mu.Unlock()

	if _, ok := store.entries["expired"]; ok {
		t.Fatal("expired approval remains after sweep")
	}
	for _, id := range []string{"boundary", "live"} {
		if _, ok := store.entries[id]; !ok {
			t.Fatalf("entry %q was swept at the strict boundary", id)
		}
	}
}

func TestMemoryMFAStoresConcurrentAccessAndSweep(t *testing.T) {
	ctx := context.Background()
	challenges := NewMemoryMFAChallengeStore()
	approvals := NewMemoryPushApprovalStore()
	var wg sync.WaitGroup

	for worker := range 4 {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 100 {
				id := fmt.Sprintf("entry-%d-%d", worker, i)
				_ = challenges.Put(ctx, &spi.MFAChallenge{ID: id, ExpiresAt: time.Now().Add(time.Hour)})
				_, _ = challenges.Consume(ctx, id)
				_ = approvals.Put(ctx, &PushApproval{ID: id, SubjectID: "subject", ExpiresAt: time.Now().Add(time.Hour)})
				_, _ = approvals.Get(ctx, id)
				_ = approvals.SetStatus(ctx, id, PushApprovalApproved)
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 100 {
			challenges.mu.Lock()
			sweepExpiredEntries(challenges.entries, time.Now(), func(entry *spi.MFAChallenge) time.Time {
				return entry.ExpiresAt
			})
			challenges.mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			approvals.mu.Lock()
			sweepExpiredEntries(approvals.entries, time.Now(), func(entry *PushApproval) time.Time {
				return entry.ExpiresAt
			})
			approvals.mu.Unlock()
		}
	}()
	wg.Wait()
}
