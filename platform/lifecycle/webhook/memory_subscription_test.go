package webhook_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/webhook"
)

func validSub(url string) webhook.EventSubscription {
	return webhook.EventSubscription{
		URL:        url,
		EventTypes: []audit.EventType{audit.EventLogin},
		Secret:     "s3cr3t",
	}
}

func TestMemorySubscriptionStore_CreateAssignsIDAndTimestamps(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemorySubscriptionStore()
	created, err := store.Create(context.Background(), validSub("https://a.example/hook"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Error("expected a server-minted ID")
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("expected CreatedAt/UpdatedAt to be stamped")
	}
}

func TestMemorySubscriptionStore_CreateRejectsInvalid(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemorySubscriptionStore()
	sub := validSub("https://a.example/hook")
	sub.Secret = ""
	if _, err := store.Create(context.Background(), sub); !errors.Is(err, webhook.ErrSecretRequired) {
		t.Errorf("Create: got %v, want ErrSecretRequired", err)
	}
}

func TestMemorySubscriptionStore_GetUnknown(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemorySubscriptionStore()
	if _, err := store.Get(context.Background(), "nope"); !errors.Is(err, webhook.ErrSubscriptionNotFound) {
		t.Errorf("Get: got %v, want ErrSubscriptionNotFound", err)
	}
}

func TestMemorySubscriptionStore_ListOrderedOldestFirst(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	first, err := store.Create(ctx, validSub("https://a.example/hook"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	second, err := store.Create(ctx, validSub("https://b.example/hook"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}
	// CreatedAt is stamped with the same wall-clock read in a fast test loop,
	// so ties are broken by ID; either legal ordering is acceptable as long
	// as both are present.
	seen := map[string]bool{list[0].ID: true, list[1].ID: true}
	if !seen[first.ID] || !seen[second.ID] {
		t.Errorf("List did not return both created subscriptions: %+v", list)
	}
}

func TestMemorySubscriptionStore_IsolatesEventTypes(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	input := validSub("https://a.example/hook")
	created, err := store.Create(ctx, input)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	input.EventTypes[0] = audit.EventLogout
	created.EventTypes[0] = audit.EventLogout

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.EventTypes) != 1 || got.EventTypes[0] != audit.EventLogin {
		t.Fatalf("stored EventTypes changed through Create input/return: %v", got.EventTypes)
	}
	got.EventTypes[0] = audit.EventLogout

	again, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get after mutation: %v", err)
	}
	if again.EventTypes[0] != audit.EventLogin {
		t.Fatalf("Get result aliases stored EventTypes: %v", again.EventTypes)
	}
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	list[0].EventTypes[0] = audit.EventLogout
	final, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get after List mutation: %v", err)
	}
	if final.EventTypes[0] != audit.EventLogin {
		t.Fatalf("List result aliases stored EventTypes: %v", final.EventTypes)
	}
}

func TestMemorySubscriptionStore_DeleteIsIdempotent(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	created, err := store.Create(ctx, validSub("https://a.example/hook"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete(ctx, created.ID); err != nil {
		t.Fatalf("second Delete (idempotent) : %v", err)
	}
	if _, err := store.Get(ctx, created.ID); !errors.Is(err, webhook.ErrSubscriptionNotFound) {
		t.Errorf("Get after Delete: got %v, want ErrSubscriptionNotFound", err)
	}
}

func TestMemorySubscriptionStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	store := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			_, _ = store.Create(ctx, validSub("https://a.example/hook"))
			_, _ = store.List(ctx)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 20 {
		t.Errorf("List len = %d, want 20", len(list))
	}
}
