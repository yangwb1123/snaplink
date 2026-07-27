package rebac

import (
	"context"
	"sync"
	"testing"
)

func TestMemoryStore_Adversarial_ConcurrentWrite(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			_ = store.Write(ctx, Tuple{
				Object:   "doc:doc-1",
				Relation: "viewer",
				Subject:  "user:alice",
			})
		}(i)
	}
	wg.Wait()

	// Should have exactly 1 tuple (writes are idempotent)
	tuples, err := store.Read(ctx, TupleFilter{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(tuples) != 1 {
		t.Errorf("expected 1 tuple (idempotent writes), got %d", len(tuples))
	}
}

func TestMemoryStore_Adversarial_ConcurrentDifferentTuples(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	const tuples = 50
	var wg sync.WaitGroup
	wg.Add(tuples)

	for i := range tuples {
		go func(n int) {
			defer wg.Done()
			_ = store.Write(ctx, Tuple{
				Object:   "doc:" + itoa(n),
				Relation: "viewer",
				Subject:  "user:alice",
			})
		}(i)
	}
	wg.Wait()

	all, err := store.Read(ctx, TupleFilter{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(all) != tuples {
		t.Errorf("expected %d tuples, got %d", tuples, len(all))
	}
}

func TestMemoryStore_Adversarial_RaceReadDuringWrite(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	// Seed some tuples
	for i := range 10 {
		_ = store.Write(ctx, Tuple{
			Object: "doc:" + itoa(i), Relation: "viewer", Subject: "user:bob",
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 50 {
			_, _ = store.Read(ctx, TupleFilter{
				Object:   "doc:1",
				Relation: "viewer",
			})
		}
	}()

	go func() {
		defer wg.Done()
		for i := range 5 {
			_ = store.Write(ctx, Tuple{
				Object: "doc:" + itoa(i), Relation: "editor", Subject: "user:admin",
			})
			_ = store.Delete(ctx, Tuple{
				Object: "doc:" + itoa(i), Relation: "viewer", Subject: "user:bob",
			})
		}
	}()

	wg.Wait()
}

func TestMemoryStore_Adversarial_WriteDeleteIdempotent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	tuple := Tuple{Object: "doc:1", Relation: "owner", Subject: "user:admin"}

	// Write twice (idempotent)
	if err := store.Write(ctx, tuple); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := store.Write(ctx, tuple); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	// Read should return 1
	tuples, _ := store.Read(ctx, TupleFilter{Object: "doc:1"})
	if len(tuples) != 1 {
		t.Errorf("expected 1 tuple, got %d", len(tuples))
	}

	// Delete twice (idempotent)
	if err := store.Delete(ctx, tuple); err != nil {
		t.Fatalf("first Delete: %v", err)
	}
	if err := store.Delete(ctx, tuple); err != nil {
		t.Fatalf("second Delete: %v", err)
	}

	tuples, _ = store.Read(ctx, TupleFilter{Object: "doc:1"})
	if len(tuples) != 0 {
		t.Errorf("expected 0 tuples after delete, got %d", len(tuples))
	}
}

func TestMemoryStore_Adversarial_FilterEdgeCases(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	// Seed
	tuples := []Tuple{
		{Object: "doc:1", Relation: "viewer", Subject: "user:alice"},
		{Object: "doc:1", Relation: "editor", Subject: "user:bob"},
		{Object: "doc:2", Relation: "viewer", Subject: "user:alice"},
	}
	for _, tup := range tuples {
		_ = store.Write(ctx, tup)
	}

	t.Run("empty filter returns all", func(t *testing.T) {
		all, _ := store.Read(ctx, TupleFilter{})
		if len(all) != 3 {
			t.Errorf("expected 3, got %d", len(all))
		}
	})

	t.Run("filter by object", func(t *testing.T) {
		result, _ := store.Read(ctx, TupleFilter{Object: "doc:1"})
		if len(result) != 2 {
			t.Errorf("expected 2, got %d", len(result))
		}
	})

	t.Run("filter by relation", func(t *testing.T) {
		result, _ := store.Read(ctx, TupleFilter{Relation: "viewer"})
		if len(result) != 2 {
			t.Errorf("expected 2, got %d", len(result))
		}
	})

	t.Run("filter by subject", func(t *testing.T) {
		result, _ := store.Read(ctx, TupleFilter{Subject: "user:bob"})
		if len(result) != 1 {
			t.Errorf("expected 1, got %d", len(result))
		}
	})

	t.Run("filter all fields", func(t *testing.T) {
		result, _ := store.Read(ctx, TupleFilter{
			Object: "doc:2", Relation: "viewer", Subject: "user:alice",
		})
		if len(result) != 1 {
			t.Errorf("expected 1, got %d", len(result))
		}
	})

	t.Run("filter no match", func(t *testing.T) {
		result, _ := store.Read(ctx, TupleFilter{Object: "nonexistent"})
		if len(result) != 0 {
			t.Errorf("expected 0, got %d", len(result))
		}
	})
}

func TestMemoryStore_Adversarial_ValidTupleRejected(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	// Tuples must have non-empty Object, Relation, Subject
	invalidCases := []Tuple{
		{Object: "", Relation: "viewer", Subject: "user:alice"},
		{Object: "doc:1", Relation: "", Subject: "user:alice"},
		{Object: "doc:1", Relation: "viewer", Subject: ""},
	}

	for _, tc := range invalidCases {
		err := store.Write(ctx, tc)
		if err == nil {
			t.Errorf("expected error for invalid tuple %+v", tc)
		} else if err != ErrInvalidTuple {
			t.Errorf("expected ErrInvalidTuple for %+v, got %v", tc, err)
		}
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
