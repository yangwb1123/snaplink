package configaudit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore_RecordAndList(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()

	if err := s.Record(ctx, Entry{Actor: "alice", Resource: "client", ResourceID: "c1"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := s.Record(ctx, Entry{Actor: "bob", Resource: "tenant", ResourceID: "t1"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries, err := s.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// Newest first.
	if entries[0].Actor != "bob" || entries[1].Actor != "alice" {
		t.Errorf("expected newest-first order [bob, alice], got [%s, %s]", entries[0].Actor, entries[1].Actor)
	}
	for _, e := range entries {
		if e.ID == "" {
			t.Errorf("Record must assign an ID when the caller left it empty")
		}
		if e.RecordedAt.IsZero() {
			t.Errorf("Record must assign RecordedAt when the caller left it zero")
		}
	}
}

func TestMemoryStore_FilterByResource(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	_ = s.Record(ctx, Entry{Resource: "client", ResourceID: "c1"})
	_ = s.Record(ctx, Entry{Resource: "tenant", ResourceID: "t1"})
	_ = s.Record(ctx, Entry{Resource: "client", ResourceID: "c2"})

	entries, err := s.List(ctx, Filter{Resource: "client"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 client entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Resource != "client" {
			t.Errorf("filter leaked a non-matching resource: %+v", e)
		}
	}
}

func TestMemoryStore_FilterBySince(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	old := time.Now().Add(-2 * time.Hour)
	_ = s.Record(ctx, Entry{Resource: "client", ResourceID: "old", RecordedAt: old})
	_ = s.Record(ctx, Entry{Resource: "client", ResourceID: "new", RecordedAt: time.Now()})

	entries, err := s.List(ctx, Filter{Since: time.Now().Add(-1 * time.Hour)})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].ResourceID != "new" {
		t.Fatalf("expected only the entry recorded after Since, got %+v", entries)
	}
}

func TestMemoryStore_LimitAndCapacityEviction(t *testing.T) {
	s := NewMemoryStore(3)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = s.Record(ctx, Entry{Resource: "client", ResourceID: string(rune('a' + i))})
	}
	if got := s.Len(); got != 3 {
		t.Fatalf("expected capacity-bounded Len() == 3, got %d", got)
	}
	entries, err := s.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after eviction, got %d", len(entries))
	}
	// The oldest two (a, b) must have been evicted; c/d/e survive.
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.ResourceID] = true
	}
	for _, want := range []string{"c", "d", "e"} {
		if !seen[want] {
			t.Errorf("expected surviving entry %q, got %+v", want, entries)
		}
	}

	limited, err := s.List(ctx, Filter{Limit: 1})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("expected Limit: 1 to return exactly 1 entry, got %d", len(limited))
	}
}

func TestMemoryStore_SatisfiesStoreInterface(t *testing.T) {
	var _ Store = NewMemoryStore(0)
}
