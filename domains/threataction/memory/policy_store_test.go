package memory

import (
	"context"
	"testing"

	"github.com/snaplink/sso/domains/threataction"
)

func TestThreatPolicyStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewThreatPolicyStore()

	// List empty store.
	policies, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected 0 policies, got %d", len(policies))
	}

	// Get non-existent.
	_, err = store.Get(ctx, "nonexistent")
	if err != threataction.ErrPolicyNotFound {
		t.Fatalf("expected ErrPolicyNotFound, got %v", err)
	}

	// Put first policy.
	p1 := threataction.ThreatPolicy{
		Name:    "critical-suspend",
		Enabled: true,
		Type:    "impossible_travel",
		Action:  threataction.ActionSuspend,
	}
	if err := store.Put(ctx, p1); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Put second policy.
	p2 := threataction.ThreatPolicy{
		Name:    "warn-notify",
		Enabled: true,
		Type:    "impossible_travel",
		Action:  threataction.ActionNotify,
	}
	if err := store.Put(ctx, p2); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// List returns both, sorted by name.
	policies, err = store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
	if policies[0].Name != "critical-suspend" {
		t.Errorf("expected first policy name critical-suspend, got %s", policies[0].Name)
	}
	if policies[1].Name != "warn-notify" {
		t.Errorf("expected second policy name warn-notify, got %s", policies[1].Name)
	}

	// Get existing policy.
	got, err := store.Get(ctx, "critical-suspend")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Action != threataction.ActionSuspend {
		t.Errorf("expected suspend action, got %s", got.Action)
	}

	// Delete policy.
	if err := store.Delete(ctx, "critical-suspend"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	policies, err = store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy after delete, got %d", len(policies))
	}

	// Delete non-existent.
	if err := store.Delete(ctx, "nonexistent"); err != threataction.ErrPolicyNotFound {
		t.Fatalf("expected ErrPolicyNotFound, got %v", err)
	}

	// Upsert replaces existing.
	updated := threataction.ThreatPolicy{
		Name:    "warn-notify",
		Enabled: false,
		Type:    "velocity_burst",
		Action:  threataction.ActionNoop,
	}
	if err := store.Put(ctx, updated); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err = store.Get(ctx, "warn-notify")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Enabled {
		t.Error("expected policy to be disabled after update")
	}
	if got.Type != "velocity_burst" {
		t.Errorf("expected type velocity_burst, got %s", got.Type)
	}
}

func TestThreatPolicyStore_Concurrency(t *testing.T) {
	ctx := context.Background()
	store := NewThreatPolicyStore()

	// Concurrent writes.
	t.Run("concurrent put", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 20; i++ {
			name := "policy-" + string(rune('a'+i))
			_ = store.Put(ctx, threataction.ThreatPolicy{
				Name:    name,
				Enabled: true,
				Type:    "impossible_travel",
				Action:  threataction.ActionSuspend,
			})
		}
	})

	// Concurrent reads.
	t.Run("concurrent list", func(t *testing.T) {
		t.Parallel()
		policies, err := store.List(ctx)
		if err != nil {
			t.Errorf("List: %v", err)
		}
		_ = policies
	})
}

func TestThreatPolicyStore_FirstMatchOrdering(t *testing.T) {
	ctx := context.Background()
	store := NewThreatPolicyStore()

	_ = store.Put(ctx, threataction.ThreatPolicy{Name: "b-critical", Enabled: true, Action: threataction.ActionSuspend})
	_ = store.Put(ctx, threataction.ThreatPolicy{Name: "a-warn", Enabled: true, Action: threataction.ActionNotify})

	policies, _ := store.List(ctx)
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
	// First policy alphabetically should be "a-warn".
	if policies[0].Name != "a-warn" {
		t.Errorf("expected first policy 'a-warn', got %s", policies[0].Name)
	}
}
