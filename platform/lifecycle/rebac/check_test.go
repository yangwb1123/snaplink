package rebac_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/platform/lifecycle/rebac"
)

func TestEngine_Check_DirectTuple(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := rebac.NewMemoryStore()
	if err := store.Write(ctx, rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: "user:alice"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	eng := rebac.NewEngine(store)

	allowed, err := eng.Check(ctx, "document:42", "viewer", "user:alice")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Error("direct tuple should grant access")
	}

	allowed, err = eng.Check(ctx, "document:42", "viewer", "user:bob")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Error("user with no tuple should NOT have access")
	}
}

func TestEngine_Check_GroupIndirection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := rebac.NewMemoryStore()
	seed := []rebac.Tuple{
		// document:42's editor relation is granted to anyone with the
		// "member" relation on group:eng — a userset reference.
		{Object: "document:42", Relation: "editor", Subject: "group:eng#member"},
		{Object: "group:eng", Relation: "member", Subject: "user:carol"},
	}
	for _, tp := range seed {
		if err := store.Write(ctx, tp); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	eng := rebac.NewEngine(store)

	allowed, err := eng.Check(ctx, "document:42", "editor", "user:carol")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Error("carol is a direct member of group:eng, so should inherit editor via the userset reference")
	}

	allowed, err = eng.Check(ctx, "document:42", "editor", "user:dave")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Error("dave is not a member of group:eng, so should NOT inherit editor")
	}
}

func TestEngine_Check_NestedGroupsNotExpanded(t *testing.T) {
	t.Parallel()
	// Deliberately deferred scope: a member that is ITSELF a userset
	// reference (a group-of-groups) is not expanded past one level.
	ctx := context.Background()
	store := rebac.NewMemoryStore()
	seed := []rebac.Tuple{
		{Object: "document:42", Relation: "editor", Subject: "group:eng#member"},
		{Object: "group:eng", Relation: "member", Subject: "group:backend#member"},
		{Object: "group:backend", Relation: "member", Subject: "user:erin"},
	}
	for _, tp := range seed {
		if err := store.Write(ctx, tp); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	eng := rebac.NewEngine(store)

	allowed, err := eng.Check(ctx, "document:42", "editor", "user:erin")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Error("erin is only a member two levels deep (group:backend -> group:eng); nested-group expansion is deferred, so this must be false")
	}

	// But a direct member of group:eng (one level) still works alongside
	// the nested (and unexpanded) entry.
	if err := store.Write(ctx, rebac.Tuple{Object: "group:eng", Relation: "member", Subject: "user:frank"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	allowed, err = eng.Check(ctx, "document:42", "editor", "user:frank")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Error("frank is a direct member of group:eng, so should inherit editor")
	}
}

func TestEngine_Check_NilEngineOrStore(t *testing.T) {
	t.Parallel()
	var nilEngine *rebac.Engine
	if _, err := nilEngine.Check(context.Background(), "document:42", "viewer", "user:alice"); !errors.Is(err, rebac.ErrNoStore) {
		t.Fatalf("nil *Engine Check error = %v, want ErrNoStore", err)
	}

	eng := rebac.NewEngine(nil)
	if _, err := eng.Check(context.Background(), "document:42", "viewer", "user:alice"); !errors.Is(err, rebac.ErrNoStore) {
		t.Fatalf("nil-store Engine Check error = %v, want ErrNoStore", err)
	}
}

// failingStore wraps a real RelationTupleStore but forces Read to error, so
// Engine.Check's fail-closed error-propagation branch runs (mirrors
// domains/permissions/handlers_test.go's failingProvider decorator — the
// real Memory store backs everything else, only Read is overridden).
type failingStore struct {
	rebac.RelationTupleStore
	err error
}

func (f failingStore) Read(context.Context, rebac.TupleFilter) ([]rebac.Tuple, error) {
	return nil, f.err
}

func TestEngine_Check_StoreErrorPropagates(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	eng := rebac.NewEngine(failingStore{RelationTupleStore: rebac.NewMemoryStore(), err: boom})
	allowed, err := eng.Check(context.Background(), "document:42", "viewer", "user:alice")
	if !errors.Is(err, boom) {
		t.Fatalf("Check error = %v, want %v", err, boom)
	}
	if allowed {
		t.Error("a failed Check must never report allowed=true")
	}
}

func TestEngine_Check_SelfReferencingUsersetNoInfiniteLoop(t *testing.T) {
	t.Parallel()
	// A group tuple that names itself as its own userset member must not
	// cause unbounded recursion — Check only ever expands one level, so
	// this terminates by construction (see package doc).
	ctx := context.Background()
	store := rebac.NewMemoryStore()
	seed := []rebac.Tuple{
		{Object: "document:42", Relation: "editor", Subject: "group:eng#member"},
		{Object: "group:eng", Relation: "member", Subject: "group:eng#member"},
	}
	for _, tp := range seed {
		if err := store.Write(ctx, tp); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	eng := rebac.NewEngine(store)

	allowed, err := eng.Check(ctx, "document:42", "editor", "user:anyone")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Error("a self-referencing userset with no direct member must not grant access")
	}
}
