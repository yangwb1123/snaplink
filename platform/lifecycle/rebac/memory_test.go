package rebac_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/platform/lifecycle/rebac"
)

func TestMemoryStore_WriteReadDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := rebac.NewMemoryStore()

	tuple := rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: "user:alice"}
	if err := store.Write(ctx, tuple); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := store.Read(ctx, rebac.TupleFilter{Object: "document:42", Relation: "viewer"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 || got[0] != tuple {
		t.Fatalf("Read = %v, want [%v]", got, tuple)
	}

	if err := store.Delete(ctx, tuple); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err = store.Read(ctx, rebac.TupleFilter{Object: "document:42", Relation: "viewer"})
	if err != nil {
		t.Fatalf("Read after delete: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Read after delete = %v, want empty", got)
	}
}

func TestMemoryStore_WriteRejectsInvalid(t *testing.T) {
	t.Parallel()
	store := rebac.NewMemoryStore()
	err := store.Write(context.Background(), rebac.Tuple{Object: "bad", Relation: "viewer", Subject: "user:alice"})
	if err == nil {
		t.Fatal("Write of an invalid tuple should error")
	}
}

func TestMemoryStore_WriteIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := rebac.NewMemoryStore()
	tuple := rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: "user:alice"}
	for i := 0; i < 3; i++ {
		if err := store.Write(ctx, tuple); err != nil {
			t.Fatalf("Write #%d: %v", i, err)
		}
	}
	got, err := store.Read(ctx, rebac.TupleFilter{Object: "document:42", Relation: "viewer"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Read after 3x Write = %v, want exactly one tuple (idempotent)", got)
	}
}

func TestMemoryStore_DeleteIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := rebac.NewMemoryStore()
	tuple := rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: "user:alice"}
	// Deleting a tuple that was never written must be a silent no-op, not
	// an error.
	if err := store.Delete(ctx, tuple); err != nil {
		t.Fatalf("Delete of absent tuple: %v", err)
	}
	if err := store.Write(ctx, tuple); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := store.Delete(ctx, tuple); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete(ctx, tuple); err != nil {
		t.Fatalf("second Delete of already-removed tuple: %v", err)
	}
}

func TestMemoryStore_ReadFilters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := rebac.NewMemoryStore()
	seed := []rebac.Tuple{
		{Object: "document:42", Relation: "viewer", Subject: "user:alice"},
		{Object: "document:42", Relation: "viewer", Subject: "user:bob"},
		{Object: "document:42", Relation: "editor", Subject: "user:alice"},
		{Object: "document:7", Relation: "viewer", Subject: "user:alice"},
	}
	for _, tp := range seed {
		if err := store.Write(ctx, tp); err != nil {
			t.Fatalf("seed Write: %v", err)
		}
	}

	// Indexed path: Object+Relation both set.
	got, err := store.Read(ctx, rebac.TupleFilter{Object: "document:42", Relation: "viewer"})
	if err != nil {
		t.Fatalf("Read indexed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Read(document:42,viewer) = %v, want 2 tuples", got)
	}

	// Indexed path narrowed further by Subject.
	got, err = store.Read(ctx, rebac.TupleFilter{Object: "document:42", Relation: "viewer", Subject: "user:bob"})
	if err != nil {
		t.Fatalf("Read indexed+subject: %v", err)
	}
	if len(got) != 1 || got[0].Subject != "user:bob" {
		t.Fatalf("Read(document:42,viewer,user:bob) = %v", got)
	}

	// Scan fallback: Subject-only filter (the reverse "what does alice
	// have" admin query), no Object/Relation set.
	got, err = store.Read(ctx, rebac.TupleFilter{Subject: "user:alice"})
	if err != nil {
		t.Fatalf("Read scan: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Read(subject=alice) = %v, want 3 tuples", got)
	}

	// Empty filter returns everything.
	got, err = store.Read(ctx, rebac.TupleFilter{})
	if err != nil {
		t.Fatalf("Read all: %v", err)
	}
	if len(got) != len(seed) {
		t.Fatalf("Read({}) = %d tuples, want %d", len(got), len(seed))
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := rebac.NewMemoryStore()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			_ = store.Write(ctx, rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: "user:alice"})
		}
	}()
	for i := 0; i < 100; i++ {
		_, _ = store.Read(ctx, rebac.TupleFilter{Object: "document:42", Relation: "viewer"})
	}
	<-done
}
