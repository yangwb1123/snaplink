package memory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/tokenpolicy"
)

// TestStore_SeedAndList proves New seeds the set and Policies returns it.
func TestStore_SeedAndList(t *testing.T) {
	t.Parallel()
	s := New(
		tokenpolicy.Policy{Name: "a", ClientID: "c1", MaxTTL: time.Minute},
		tokenpolicy.Policy{Name: "b", MaxRefreshDepth: 3},
	)
	got, err := s.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Fatalf("Policies = %+v, want [a b]", got)
	}
}

// TestStore_EmptyIsEmpty proves a store with no seed returns an empty set, not
// an error.
func TestStore_EmptyIsEmpty(t *testing.T) {
	t.Parallel()
	got, err := New().Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Policies = %+v, want empty", got)
	}
}

// TestStore_NewFromSlice proves the ParseYAML-shaped constructor.
func TestStore_NewFromSlice(t *testing.T) {
	t.Parallel()
	in := []tokenpolicy.Policy{{Name: "x"}}
	got, _ := NewFromSlice(in).Policies(context.Background())
	if len(got) != 1 || got[0].Name != "x" {
		t.Fatalf("Policies = %+v", got)
	}
}

// TestStore_ReplaceIsCopyOnWrite proves Replace swaps the set atomically and a
// slice returned BEFORE a Replace is never mutated by it (the read-only
// contract the hot path relies on).
func TestStore_ReplaceIsCopyOnWrite(t *testing.T) {
	t.Parallel()
	s := New(tokenpolicy.Policy{Name: "old"})
	before, _ := s.Policies(context.Background())

	s.Replace([]tokenpolicy.Policy{{Name: "new1"}, {Name: "new2"}})

	if len(before) != 1 || before[0].Name != "old" {
		t.Fatalf("previously returned slice was mutated: %+v", before)
	}
	after, _ := s.Policies(context.Background())
	if len(after) != 2 || after[0].Name != "new1" {
		t.Fatalf("post-Replace Policies = %+v, want [new1 new2]", after)
	}
}

// TestStore_ConcurrentReadWrite proves the store is race-free under concurrent
// Policies reads and Replace writes (run with -race).
func TestStore_ConcurrentReadWrite(t *testing.T) {
	t.Parallel()
	s := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = s.Policies(context.Background()) }()
		go func() { defer wg.Done(); s.Replace([]tokenpolicy.Policy{{Name: "r"}}) }()
	}
	wg.Wait()
}

// staticProbe pins the interface guard: the memory store satisfies the SPI.
var _ tokenpolicy.Store = (*Store)(nil)
