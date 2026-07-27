package webhook

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryDeadLetterStore_Adversarial_ConcurrentAdd(t *testing.T) {
	store := NewMemoryDeadLetterStore(100)
	ctx := context.Background()

	ids := make([]string, 0)
	var mu sync.Mutex

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			entry, _ := store.Add(ctx, DeadLetterEntry{
				SubscriptionID: "sub-" + itoa(n),
				LastError:      "timeout",
				LastFailedAt:   time.Now(),
			})
			mu.Lock()
			ids = append(ids, entry.ID)
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if len(ids) != goroutines {
		t.Errorf("expected %d entries, got %d", goroutines, len(ids))
	}

	for _, id := range ids {
		entry, err := store.Get(ctx, id)
		if err != nil {
			t.Errorf("entry %q missing after concurrent add: %v", id, err)
		} else if entry.SubscriptionID == "" {
			t.Errorf("entry %q has empty SubscriptionID", id)
		}
	}
}

func TestMemoryDeadLetterStore_Adversarial_ConcurrentAddSameID(t *testing.T) {
	store := NewMemoryDeadLetterStore(100)
	ctx := context.Background()

	// Pre-create with a known ID so concurrent adds try to upsert
	store.Add(ctx, DeadLetterEntry{
		ID:             "known-id",
		SubscriptionID: "known-sub",
		LastError:      "original",
		LastFailedAt:   time.Now(),
	})

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			store.Add(ctx, DeadLetterEntry{
				ID:             "known-id",
				SubscriptionID: "known-sub",
				LastError:      "updated",
				LastFailedAt:   time.Now(),
			})
		}()
	}
	wg.Wait()

	entry, err := store.Get(ctx, "known-id")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.SubscriptionID != "known-sub" {
		t.Errorf("expected 'known-sub', got %q", entry.SubscriptionID)
	}
}

func TestMemoryDeadLetterStore_Adversarial_RaceAddAndList(t *testing.T) {
	store := NewMemoryDeadLetterStore(50)
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := range 30 {
			store.Add(ctx, DeadLetterEntry{
				SubscriptionID: "sub-" + itoa(i),
				LastFailedAt:   time.Now(),
				LastError:      "err",
			})
		}
	}()

	go func() {
		defer wg.Done()
		for range 20 {
			store.List(ctx, DeadLetterFilter{Limit: 100})
		}
	}()

	go func() {
		defer wg.Done()
		for i := range 15 {
			store.Delete(ctx, "sub-"+itoa(i))
		}
	}()

	wg.Wait()
}

func TestMemoryDeadLetterStore_Adversarial_CapacityWithConcurrent(t *testing.T) {
	store := NewMemoryDeadLetterStore(10)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store.Add(ctx, DeadLetterEntry{
				SubscriptionID: "overflow-" + itoa(n),
				LastFailedAt:   time.Now(),
				LastError:      "err",
			})
		}(i)
	}
	wg.Wait()

	entries, _ := store.List(ctx, DeadLetterFilter{Limit: 100})
	if len(entries) > 10 {
		t.Errorf("expected at most 10 entries (capacity), got %d", len(entries))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
