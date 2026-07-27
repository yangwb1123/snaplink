package sqlite

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// facetSeed is the shared event corpus for the conformance suite. The
// same slice is recorded into both backends so any divergence in facet
// aggregation is a backend bug, not a fixture mismatch.
func facetSeed() (time.Time, []*audit.Event) {
	base := time.Date(2026, 2, 1, 9, 0, 0, 0, time.UTC)
	return base, []*audit.Event{
		{ID: "a", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: base, ClientID: "web", Provider: "password", ActorID: "alice"},
		{ID: "b", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure, Timestamp: base.Add(1 * time.Minute), ClientID: "web", Provider: "password", ActorID: "bob"},
		{ID: "c", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: base.Add(2 * time.Minute), ClientID: "mobile", Provider: "phone", ActorID: "alice"},
		{ID: "d", Type: audit.EventLogout, Outcome: audit.OutcomeSuccess, Timestamp: base.Add(3 * time.Minute), ClientID: "web", ActorID: "alice"},
		{ID: "e", Type: audit.EventLogin, Outcome: audit.OutcomeFailure, Timestamp: base.Add(4 * time.Minute), ClientID: "mobile", Provider: "phone", ActorID: "carol"},
	}
}

// TestFacets_MemoryEqualsSQLite is the equivalence suite: the same events
// seeded into MemorySink and the SQLite Sink MUST produce byte-identical
// Facets across a representative set of queries (unfiltered, by-type,
// by-outcome, by-client, time-windowed, empty-result). This locks the two
// real backends to one facet contract — the same posture the permissions
// ConformanceSuite enforces for memory/sqlite.
func TestFacets_MemoryEqualsSQLite(t *testing.T) {
	t.Parallel()
	base, seed := facetSeed()

	mem := audit.NewMemorySink(100)
	sq := newTestSink(t)
	for _, e := range seed {
		// Copy so the two backends don't share *Event identity (Record
		// may stamp fields).
		ce := *e
		if err := mem.Record(context.Background(), &ce); err != nil {
			t.Fatalf("memory record %s: %v", e.ID, err)
		}
		ce2 := *e
		if err := sq.Record(context.Background(), &ce2); err != nil {
			t.Fatalf("sqlite record %s: %v", e.ID, err)
		}
	}

	cases := []struct {
		name string
		q    audit.Query
	}{
		{"all", audit.Query{}},
		{"by-type-login", audit.Query{Type: audit.EventLogin}},
		{"by-outcome-failure", audit.Query{Outcome: audit.OutcomeFailure}},
		{"by-client-web", audit.Query{ClientID: "web"}},
		{"by-provider-phone", audit.Query{Provider: "phone"}},
		{"by-actor-alice", audit.Query{ActorID: "alice"}},
		{"since-window", audit.Query{Since: base.Add(2 * time.Minute)}},
		{"until-window", audit.Query{Until: base.Add(2 * time.Minute)}},
		{"since-until-window", audit.Query{Since: base.Add(1 * time.Minute), Until: base.Add(4 * time.Minute)}},
		{"limit-offset-ignored", audit.Query{Limit: 1, Offset: 3}},
		{"empty-result", audit.Query{ClientID: "no-such-client"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			memF, err := mem.Facets(context.Background(), tc.q)
			if err != nil {
				t.Fatalf("memory facets: %v", err)
			}
			sqF, err := sq.Facets(context.Background(), tc.q)
			if err != nil {
				t.Fatalf("sqlite facets: %v", err)
			}
			if !reflect.DeepEqual(memF, sqF) {
				t.Errorf("facet divergence\n memory = %+v\n sqlite = %+v", memF, sqF)
			}
		})
	}
}

// TestFacets_Counts pins the absolute counts for the unfiltered window so
// a bug that keeps memory==sqlite but breaks BOTH (e.g. a fixture or
// grouping mistake) is still caught.
func TestFacets_Counts(t *testing.T) {
	t.Parallel()
	_, seed := facetSeed()
	sq := newTestSink(t)
	for _, e := range seed {
		ce := *e
		if err := sq.Record(context.Background(), &ce); err != nil {
			t.Fatalf("record %s: %v", e.ID, err)
		}
	}
	f, err := sq.Facets(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("facets: %v", err)
	}
	if f.Total != 5 {
		t.Errorf("Total = %d, want 5", f.Total)
	}
	if f.Outcomes[audit.OutcomeSuccess] != 3 || f.Outcomes[audit.OutcomeFailure] != 2 {
		t.Errorf("Outcomes = %v", f.Outcomes)
	}
	if f.Types[audit.EventLogin] != 3 || f.Types[audit.EventLoginFailure] != 1 || f.Types[audit.EventLogout] != 1 {
		t.Errorf("Types = %v", f.Types)
	}
	if f.Clients["web"] != 3 || f.Clients["mobile"] != 2 {
		t.Errorf("Clients = %v", f.Clients)
	}
	// Provider empty on the logout event (id "d") MUST NOT appear as a "" key.
	if _, ok := f.Providers[""]; ok {
		t.Errorf("empty provider leaked into facets: %v", f.Providers)
	}
	if f.Providers["password"] != 2 || f.Providers["phone"] != 2 {
		t.Errorf("Providers = %v", f.Providers)
	}
}
