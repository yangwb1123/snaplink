package audit_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

func TestMemorySink_AssignsIDWhenEmpty(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(10)
	e := &audit.Event{Type: audit.EventLogin}
	if err := s.Record(context.Background(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if e.ID == "" {
		t.Fatal("Record should assign a non-empty ID when input ID is blank")
	}
}

func TestMemorySink_PreservesGivenID(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(10)
	e := &audit.Event{ID: "preset-id", Type: audit.EventLogin}
	_ = s.Record(context.Background(), e)
	if e.ID != "preset-id" {
		t.Fatalf("ID overwritten: got %q", e.ID)
	}
}

func TestMemorySink_GetReturnsRecordedEvent(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(10)
	e := &audit.Event{Type: audit.EventLogin}
	_ = s.Record(context.Background(), e)

	got, err := s.Get(context.Background(), e.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != e {
		t.Fatal("Get should return the exact recorded pointer")
	}
}

func TestMemorySink_GetUnknownReturnsErrEventNotFound(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(10)
	_, err := s.Get(context.Background(), "no-such-id")
	if !errors.Is(err, audit.ErrEventNotFound) {
		t.Fatalf("expected ErrEventNotFound, got %v", err)
	}
}

func TestMemorySink_LenTracksRecords(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(3)
	if got := s.Len(); got != 0 {
		t.Fatalf("Len at start = %d, want 0", got)
	}
	for range 2 {
		_ = s.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	}
	if got := s.Len(); got != 2 {
		t.Fatalf("Len after 2 records = %d, want 2", got)
	}
}

func TestMemorySink_RingBufferEvictsOldest(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(3)

	events := make([]*audit.Event, 5)
	for i := range events {
		events[i] = &audit.Event{Type: audit.EventLogin, ActorID: "u"}
		_ = s.Record(context.Background(), events[i])
	}

	// Capacity is 3 — only the last three (events[2..4]) should remain.
	if got := s.Len(); got != 3 {
		t.Fatalf("Len = %d, want 3 (capacity)", got)
	}

	// Evicted events: Get should fail.
	for _, evicted := range events[:2] {
		if _, err := s.Get(context.Background(), evicted.ID); !errors.Is(err, audit.ErrEventNotFound) {
			t.Errorf("event %q should have been evicted; got err = %v", evicted.ID, err)
		}
	}
	// Retained events: Get should succeed.
	for _, kept := range events[2:] {
		if _, err := s.Get(context.Background(), kept.ID); err != nil {
			t.Errorf("event %q should still be retrievable; got err = %v", kept.ID, err)
		}
	}
}

func TestMemorySink_QueryReturnsNewestFirst(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(10)
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		_ = s.Record(context.Background(), &audit.Event{
			Type:      audit.EventLogin,
			ActorID:   "u",
			Timestamp: t0.Add(time.Duration(i) * time.Minute),
		})
	}

	got, err := s.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d events, want 5", len(got))
	}
	// Verify newest first.
	for i := 1; i < len(got); i++ {
		if got[i].Timestamp.After(got[i-1].Timestamp) {
			t.Fatalf("results out of order at i=%d: %v then %v", i, got[i-1].Timestamp, got[i].Timestamp)
		}
	}
}

func TestMemorySink_QueryAppliesFilter(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(10)
	_ = s.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "alice"})
	_ = s.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "bob"})
	_ = s.Record(context.Background(), &audit.Event{Type: audit.EventLogout, ActorID: "alice"})

	got, err := s.Query(context.Background(), audit.Query{Type: audit.EventLogin, ActorID: "alice"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].ActorID != "alice" || got[0].Type != audit.EventLogin {
		t.Errorf("unexpected event: %+v", got[0])
	}
}

func TestMemorySink_QueryAppliesLimitAndOffset(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(20)
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	for i := range 10 {
		_ = s.Record(context.Background(), &audit.Event{
			Type:      audit.EventLogin,
			ActorID:   "u",
			Timestamp: t0.Add(time.Duration(i) * time.Minute),
		})
	}

	page1, _ := s.Query(context.Background(), audit.Query{Limit: 3, Offset: 0})
	page2, _ := s.Query(context.Background(), audit.Query{Limit: 3, Offset: 3})

	if len(page1) != 3 || len(page2) != 3 {
		t.Fatalf("page sizes = %d / %d, want 3 / 3", len(page1), len(page2))
	}
	// Pages should not overlap (newest-first ordering means page2 has older items).
	for _, p1 := range page1 {
		for _, p2 := range page2 {
			if p1 == p2 {
				t.Fatal("pages should not overlap")
			}
		}
	}
}

func TestMemorySink_QueryOffsetBeyondLengthReturnsEmpty(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(10)
	for range 3 {
		_ = s.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	}
	got, err := s.Query(context.Background(), audit.Query{Limit: 5, Offset: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("offset past length should yield empty page; got %d", len(got))
	}
}

func TestMemorySink_QueryEmptySinkReturnsEmpty(t *testing.T) {
	t.Parallel()
	s := audit.NewMemorySink(10)
	got, err := s.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %v", got)
	}
}

func TestNewMemorySink_NonPositiveUsesDefault(t *testing.T) {
	t.Parallel()
	// Sentinel: NewMemorySink(0) and (-1) should not panic, should accept records.
	for _, capacity := range []int{0, -1} {
		s := audit.NewMemorySink(capacity)
		if err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
			t.Fatalf("Record on default-sized sink (cap=%d): %v", capacity, err)
		}
		if s.Len() != 1 {
			t.Fatalf("Len = %d, want 1", s.Len())
		}
	}
}

func TestMemorySink_ConcurrentRecord(t *testing.T) {
	t.Parallel()
	// Race detector verifies thread safety. With `-race` enabled this catches
	// concurrent map writes or buffer corruption.
	const goroutines = 20
	const perGoroutine = 100
	const capacity = goroutines * perGoroutine // big enough to hold them all

	s := audit.NewMemorySink(capacity)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range perGoroutine {
				_ = s.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "u"})
			}
		}()
	}
	wg.Wait()

	if got := s.Len(); got != capacity {
		t.Fatalf("Len = %d, want %d", got, capacity)
	}
}

func TestMemorySink_RingBufferWrapDoesNotDoubleCount(t *testing.T) {
	t.Parallel()
	// Specifically exercise the boundary where (head+1)%capacity == 0
	// for the first time (transition full=false → true).
	s := audit.NewMemorySink(3)
	for range 3 {
		_ = s.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	}
	if got := s.Len(); got != 3 {
		t.Fatalf("Len at exactly capacity = %d, want 3", got)
	}
	// Next record should evict one, not grow.
	_ = s.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if got := s.Len(); got != 3 {
		t.Fatalf("Len after wrap = %d, want 3", got)
	}
}
