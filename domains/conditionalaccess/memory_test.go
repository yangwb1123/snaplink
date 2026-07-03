package conditionalaccess

import (
	"context"
	"sync"
	"testing"
)

func TestMemoryStore_PutGetListDelete(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	if _, ok, err := s.Get(ctx, "missing"); err != nil || ok {
		t.Fatalf("get missing: ok=%v err=%v, want false/nil", ok, err)
	}
	if list, err := s.List(ctx); err != nil || len(list) != 0 {
		t.Fatalf("empty list: len=%d err=%v", len(list), err)
	}

	p := policy("p1", 5, Conditions{UserMemberOf: []string{"admin"}}, Actions{Deny: true})
	if err := s.Put(ctx, p); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok, err := s.Get(ctx, "p1")
	if err != nil || !ok {
		t.Fatalf("get p1: ok=%v err=%v", ok, err)
	}
	if got.Priority != 5 || len(got.Conditions.UserMemberOf) != 1 {
		t.Fatalf("get returned unexpected policy: %+v", got)
	}

	// Upsert replaces by name.
	if err := s.Put(ctx, policy("p1", 9, Conditions{}, Actions{Allow: true})); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _, _ = s.Get(ctx, "p1")
	if got.Priority != 9 || !got.Actions.Allow {
		t.Fatalf("upsert did not replace: %+v", got)
	}

	if err := s.Delete(ctx, "p1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, _ := s.Get(ctx, "p1"); ok {
		t.Fatal("policy still present after delete")
	}
	// Delete is idempotent.
	if err := s.Delete(ctx, "p1"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestMemoryStore_PutValidates(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if err := s.Put(ctx, Policy{Name: "", Enabled: true}); err == nil {
		t.Error("put with empty name should fail validation")
	}
	if err := s.Put(ctx, Policy{Name: "bad", Enabled: true, Conditions: Conditions{RiskScore: "??"}}); err == nil {
		t.Error("put with malformed comparison should fail validation")
	}
	if err := s.Put(ctx, Policy{Name: "bad-time", Enabled: true, Conditions: Conditions{TimeAfter: "25:99"}}); err == nil {
		t.Error("put with malformed time should fail validation")
	}
}

func TestMemoryStore_CloneIsolation(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	groups := []string{"admin"}
	scopes := []string{"admin:read"}
	managed := boolPtr(true)
	if err := s.Put(ctx, Policy{
		Name: "p", Enabled: true,
		Conditions: Conditions{UserMemberOf: groups, DeviceManaged: managed},
		Actions:    Actions{RestrictScopes: scopes},
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Mutating the caller's slices/pointer after Put must not reach the store.
	groups[0] = "mutated"
	scopes[0] = "mutated"
	*managed = false

	got, _, _ := s.Get(ctx, "p")
	if got.Conditions.UserMemberOf[0] != "admin" {
		t.Errorf("stored group mutated: %v", got.Conditions.UserMemberOf)
	}
	if got.Actions.RestrictScopes[0] != "admin:read" {
		t.Errorf("stored scope mutated: %v", got.Actions.RestrictScopes)
	}
	if got.Conditions.DeviceManaged == nil || !*got.Conditions.DeviceManaged {
		t.Errorf("stored device.managed mutated: %v", got.Conditions.DeviceManaged)
	}

	// Mutating a returned copy must not reach the store either.
	got.Conditions.UserMemberOf[0] = "again"
	again, _, _ := s.Get(ctx, "p")
	if again.Conditions.UserMemberOf[0] != "admin" {
		t.Errorf("returned copy aliased store: %v", again.Conditions.UserMemberOf)
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := "p"
			_ = s.Put(ctx, policy(name, n, Conditions{}, Actions{Allow: true}))
			_, _, _ = s.Get(ctx, name)
			_, _ = s.List(ctx)
		}(i)
	}
	wg.Wait()
}
