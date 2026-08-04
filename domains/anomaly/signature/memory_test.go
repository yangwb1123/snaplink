package signature

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore_RecordAndSeen(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Now()

	store.Record(ctx, Entry{
		Signature: "abc123",
		SubjectID: "user1",
		Outcome:   "success",
		Timestamp: now.Add(-time.Minute),
	})

	since := now.Add(-time.Hour)
	seen, _ := store.Seen(ctx, "abc123", since, "")
	if !seen {
		t.Error("expected signature to be seen")
	}

	seen, _ = store.Seen(ctx, "abc123", since, "user1")
	if !seen {
		t.Error("expected signature to be seen for user1")
	}

	seen, _ = store.Seen(ctx, "abc123", since, "user2")
	if seen {
		t.Error("expected signature NOT to be seen for user2")
	}
}

func TestMemoryStore_EmptySignature(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	store.Record(ctx, Entry{Signature: ""})
	seen, _ := store.Seen(ctx, "", time.Now().Add(-time.Hour), "")
	if seen {
		t.Error("empty signature should not be seen")
	}
}

func TestMemoryStore_DistinctCount(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Now()

	sigs := []string{"a1", "a2", "b1", "a1", "a3"}
	for i, s := range sigs {
		store.Record(ctx, Entry{
			Signature: s,
			Timestamp: now.Add(-time.Duration(len(sigs)-i) * time.Second),
		})
	}

	since := now.Add(-time.Hour)
	count, _ := store.DistinctCount(ctx, "", since)
	if count != 4 {
		t.Errorf("expected 4 distinct, got %d", count)
	}

	count, _ = store.DistinctCount(ctx, "a", since)
	if count != 3 {
		t.Errorf("expected 3 distinct with prefix 'a', got %d", count)
	}
}

func TestMemoryStore_PruneOlder(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Now()

	store.Record(ctx, Entry{Signature: "old", Timestamp: now.Add(-2 * time.Hour)})
	store.Record(ctx, Entry{Signature: "recent", Timestamp: now.Add(-time.Minute)})

	removed, _ := store.PruneOlder(ctx, now.Add(-time.Hour))
	if removed != 1 {
		t.Errorf("expected 1 pruned, got %d", removed)
	}

	seen, _ := store.Seen(ctx, "old", now.Add(-3*time.Hour), "")
	if seen {
		t.Error("pruned signature should not be seen")
	}
}

func TestMemoryStore_Concurrency(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	done := make(chan struct{}, 2)
	go func() {
		for i := 0; i < 100; i++ {
			store.Record(ctx, Entry{Signature: "sig", Timestamp: time.Now()})
		}
		done <- struct{}{}
	}()
	go func() {
		for i := 0; i < 100; i++ {
			store.Seen(ctx, "sig", time.Now().Add(-time.Hour), "")
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
