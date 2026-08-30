package memorystoreoauth

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
)

func cibaTestRequest(expiresAt time.Time) *oauth.CIBARequest {
	return &oauth.CIBARequest{
		ClientID:  "client",
		SubjectID: "subject",
		ExpiresAt: expiresAt,
		Status:    oauth.CIBAPending,
	}
}

func TestMemoryCIBAStoreSweepOnIssue(t *testing.T) {
	now := time.Now()
	store := NewMemoryCIBAStore()
	store.entries["expired"] = &oauth.CIBARequest{ExpiresAt: now.Add(-time.Second)}
	store.entries["live"] = &oauth.CIBARequest{ExpiresAt: now.Add(time.Hour)}
	store.lastSweep.Store(now.Add(-sweepInterval).UnixNano())

	id, err := store.Issue(context.Background(), cibaTestRequest(now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, ok := store.entries["expired"]; ok {
		t.Fatal("expired CIBA request was not swept on Issue")
	}
	for _, key := range []string{"live", id} {
		if _, ok := store.entries[key]; !ok {
			t.Fatalf("live CIBA request %q was swept", key)
		}
	}
}

func TestMemoryCIBAStoreSweepStrictBoundary(t *testing.T) {
	now := time.Now()
	store := NewMemoryCIBAStore()
	store.entries["expired"] = &oauth.CIBARequest{ExpiresAt: now.Add(-time.Nanosecond)}
	store.entries["boundary"] = &oauth.CIBARequest{ExpiresAt: now}
	store.entries["live"] = &oauth.CIBARequest{ExpiresAt: now.Add(time.Nanosecond)}

	store.mu.Lock()
	sweepExpiredEntries(store.entries, now)
	store.mu.Unlock()

	if _, ok := store.entries["expired"]; ok {
		t.Fatal("expired CIBA request remains after sweep")
	}
	for _, id := range []string{"boundary", "live"} {
		if _, ok := store.entries[id]; !ok {
			t.Fatalf("entry %q was swept at the strict boundary", id)
		}
	}
}

func TestMemoryCIBAStoreConcurrentAccessAndSweep(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCIBAStore()
	initialID, err := store.Issue(ctx, cibaTestRequest(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("initial Issue: %v", err)
	}

	var wg sync.WaitGroup
	for worker := range 4 {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 100 {
				_, _ = store.Issue(ctx, &oauth.CIBARequest{
					ClientID:  fmt.Sprintf("client-%d", worker),
					SubjectID: fmt.Sprintf("subject-%d", i),
					ExpiresAt: time.Now().Add(time.Hour),
				})
				_, _ = store.Get(ctx, initialID)
				_ = store.SetStatus(ctx, initialID, oauth.CIBAApproved)
				_ = store.UpdateLastPoll(ctx, initialID, time.Now())
				_, _ = store.ConsumeIfApproved(ctx, initialID)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			store.mu.Lock()
			sweepExpiredEntries(store.entries, time.Now())
			store.mu.Unlock()
		}
	}()
	wg.Wait()
}
