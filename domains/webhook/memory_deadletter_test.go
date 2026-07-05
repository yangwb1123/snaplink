package webhook_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/domains/webhook"
	"github.com/snaplink/sso/platform/audit"
)

func TestMemoryDeadLetterStore_AddAssignsID(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemoryDeadLetterStore(0)
	entry, err := store.Add(context.Background(), webhook.DeadLetterEntry{
		SubscriptionID: "sub-1",
		URL:            "https://a.example/hook",
		Event:          audit.Event{Type: audit.EventLogin},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if entry.ID == "" {
		t.Error("expected a server-minted ID")
	}
}

func TestMemoryDeadLetterStore_AddUpsertsByID(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemoryDeadLetterStore(0)
	ctx := context.Background()
	entry, err := store.Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-1", Attempts: 1})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	entry.Attempts = 2
	entry.LastError = "still failing"
	updated, err := store.Add(ctx, entry)
	if err != nil {
		t.Fatalf("Add (upsert): %v", err)
	}
	if updated.ID != entry.ID {
		t.Fatalf("upsert must preserve ID: got %s want %s", updated.ID, entry.ID)
	}
	got, err := store.Get(ctx, entry.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Attempts != 2 || got.LastError != "still failing" {
		t.Errorf("Get after upsert = %+v, want Attempts=2 LastError=%q", got, "still failing")
	}
}

func TestMemoryDeadLetterStore_GetUnknown(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemoryDeadLetterStore(0)
	if _, err := store.Get(context.Background(), "nope"); !errors.Is(err, webhook.ErrDeadLetterNotFound) {
		t.Errorf("Get: got %v, want ErrDeadLetterNotFound", err)
	}
}

func TestMemoryDeadLetterStore_CapacityEvictsOldest(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemoryDeadLetterStore(2)
	ctx := context.Background()
	first, _ := store.Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-1"})
	second, _ := store.Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-1"})
	third, _ := store.Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-1"})

	if _, err := store.Get(ctx, first.ID); !errors.Is(err, webhook.ErrDeadLetterNotFound) {
		t.Errorf("oldest entry should have been evicted, got err=%v", err)
	}
	if _, err := store.Get(ctx, second.ID); err != nil {
		t.Errorf("second entry should still be present: %v", err)
	}
	if _, err := store.Get(ctx, third.ID); err != nil {
		t.Errorf("third entry should still be present: %v", err)
	}
}

func TestMemoryDeadLetterStore_ListFiltersBySubscriptionAndNewestFirst(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemoryDeadLetterStore(0)
	ctx := context.Background()
	_, _ = store.Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-1"})
	_, _ = store.Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-2"})
	third, _ := store.Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-1"})

	list, err := store.List(ctx, webhook.DeadLetterFilter{SubscriptionID: "sub-1"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}
	if list[0].ID != third.ID {
		t.Errorf("List must return newest first: got %+v", list)
	}
}

func TestMemoryDeadLetterStore_ListRespectsLimit(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemoryDeadLetterStore(0)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _ = store.Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-1"})
	}
	list, err := store.List(ctx, webhook.DeadLetterFilter{Limit: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("List len = %d, want 2", len(list))
	}
}

func TestMemoryDeadLetterStore_DeleteIsIdempotent(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemoryDeadLetterStore(0)
	ctx := context.Background()
	entry, _ := store.Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-1"})
	if err := store.Delete(ctx, entry.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete(ctx, entry.ID); err != nil {
		t.Fatalf("second Delete (idempotent): %v", err)
	}
	if _, err := store.Get(ctx, entry.ID); !errors.Is(err, webhook.ErrDeadLetterNotFound) {
		t.Errorf("Get after Delete: got %v, want ErrDeadLetterNotFound", err)
	}
}
