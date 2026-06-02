package audit

import (
	"context"
	"testing"
	"time"
)

// TestMemorySink_Facets covers the four bounded dimensions + the
// empty-value skip rule + the Since/Until window honoring on the memory
// backend directly (the cross-backend equivalence lives in
// audit/sqlite/facets_conformance_test.go).
func TestMemorySink_Facets(t *testing.T) {
	m := NewMemorySink(100)
	base := time.Date(2026, 2, 1, 9, 0, 0, 0, time.UTC)
	seed := []*Event{
		{Type: EventLogin, Outcome: OutcomeSuccess, Timestamp: base, ClientID: "web", Provider: "password"},
		{Type: EventLoginFailure, Outcome: OutcomeFailure, Timestamp: base.Add(time.Minute), ClientID: "web", Provider: "password"},
		{Type: EventLogout, Outcome: OutcomeSuccess, Timestamp: base.Add(2 * time.Minute), ClientID: "web"}, // no provider
	}
	for _, e := range seed {
		if err := m.Record(context.Background(), e); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	f, err := m.Facets(context.Background(), Query{})
	if err != nil {
		t.Fatalf("facets: %v", err)
	}
	if f.Total != 3 {
		t.Errorf("Total = %d, want 3", f.Total)
	}
	if f.Outcomes[OutcomeSuccess] != 2 || f.Outcomes[OutcomeFailure] != 1 {
		t.Errorf("Outcomes = %v", f.Outcomes)
	}
	if f.Types[EventLogin] != 1 || f.Types[EventLoginFailure] != 1 || f.Types[EventLogout] != 1 {
		t.Errorf("Types = %v", f.Types)
	}
	if f.Clients["web"] != 3 {
		t.Errorf("Clients = %v", f.Clients)
	}
	// Provider absent on the logout event MUST NOT create a "" bucket.
	if _, ok := f.Providers[""]; ok {
		t.Errorf("empty provider leaked: %v", f.Providers)
	}
	if f.Providers["password"] != 2 {
		t.Errorf("Providers = %v", f.Providers)
	}
}

// TestMemorySink_FacetsWindowed proves Since/Until narrows the corpus
// before grouping (the facet window == the filter window).
func TestMemorySink_FacetsWindowed(t *testing.T) {
	m := NewMemorySink(100)
	base := time.Date(2026, 2, 1, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		_ = m.Record(context.Background(), &Event{
			Type: EventLogin, Outcome: OutcomeSuccess,
			Timestamp: base.Add(time.Duration(i) * time.Minute), ClientID: "web",
		})
	}
	// Window covers only the middle event.
	f, err := m.Facets(context.Background(), Query{
		Since: base.Add(30 * time.Second),
		Until: base.Add(90 * time.Second),
	})
	if err != nil {
		t.Fatalf("facets: %v", err)
	}
	if f.Total != 1 {
		t.Errorf("windowed Total = %d, want 1", f.Total)
	}
}

// TestMemorySink_FacetsEmpty proves a zero-match query returns empty
// (non-nil) maps so the JSON serializes objects, not null.
func TestMemorySink_FacetsEmpty(t *testing.T) {
	m := NewMemorySink(100)
	f, err := m.Facets(context.Background(), Query{})
	if err != nil {
		t.Fatalf("facets: %v", err)
	}
	if f.Total != 0 {
		t.Errorf("Total = %d, want 0", f.Total)
	}
	if f.Outcomes == nil || f.Types == nil || f.Clients == nil || f.Providers == nil {
		t.Errorf("dimension maps must be initialized: %+v", f)
	}
}

// writeOnlyStub is a Sink that only writes (no facet support) — proves
// the optional-interface type-assert in AsyncSink/MultiSink yields
// ErrFacetsUnsupported rather than implementing facets.
type writeOnlyStub struct{}

func (writeOnlyStub) Record(context.Context, *Event) error           { return nil }
func (writeOnlyStub) Query(context.Context, Query) ([]*Event, error) { return nil, nil }
func (writeOnlyStub) Get(context.Context, string) (*Event, error)    { return nil, ErrEventNotFound }

// TestAsyncSink_FacetsDelegatesAndFallsBack proves AsyncSink forwards to
// a FacetQuerier inner sink and reports ErrFacetsUnsupported otherwise.
func TestAsyncSink_FacetsDelegatesAndFallsBack(t *testing.T) {
	// Delegates to a facet-capable inner sink.
	mem := NewMemorySink(10)
	_ = mem.Record(context.Background(), &Event{Type: EventLogin, Outcome: OutcomeSuccess, ClientID: "web"})
	a := NewAsyncSink(mem)
	f, err := a.Facets(context.Background(), Query{})
	if err != nil {
		t.Fatalf("delegated facets: %v", err)
	}
	if f.Total != 1 {
		t.Errorf("Total = %d, want 1", f.Total)
	}

	// Falls back when the inner sink lacks facet support.
	b := NewAsyncSink(writeOnlyStub{})
	if _, err := b.Facets(context.Background(), Query{}); err == nil {
		t.Fatal("expected ErrFacetsUnsupported from write-only inner sink")
	}
}

// TestMultiSink_FacetsPicksFacetCapableSink proves MultiSink delegates to
// the first FacetQuerier and reports unsupported when none qualifies.
func TestMultiSink_FacetsPicksFacetCapableSink(t *testing.T) {
	mem := NewMemorySink(10)
	_ = mem.Record(context.Background(), &Event{Type: EventLogin, Outcome: OutcomeSuccess, ClientID: "web"})
	// write-only first, facet-capable second — MultiSink must skip past
	// the write-only sink, exactly like Get/Query do.
	multi := NewMultiSink(writeOnlyStub{}, mem)
	f, err := multi.Facets(context.Background(), Query{})
	if err != nil {
		t.Fatalf("multi facets: %v", err)
	}
	if f.Total != 1 {
		t.Errorf("Total = %d, want 1", f.Total)
	}

	none := NewMultiSink(writeOnlyStub{})
	if _, err := none.Facets(context.Background(), Query{}); err == nil {
		t.Fatal("expected ErrFacetsUnsupported with no facet-capable sink")
	}
}
