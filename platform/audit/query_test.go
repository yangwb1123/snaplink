package audit_test

import (
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

func TestQuery_Match_EmptyQueryMatchesEverything(t *testing.T) {
	t.Parallel()
	q := audit.Query{}
	e := &audit.Event{
		Type:     audit.EventLogin,
		ActorID:  "u",
		ClientID: "c",
		Outcome:  audit.OutcomeSuccess,
	}
	if !q.Match(e) {
		t.Fatal("empty Query should match any event")
	}
}

func TestQuery_Match_FieldFilters(t *testing.T) {
	t.Parallel()
	base := &audit.Event{
		Type:      audit.EventLogin,
		ActorID:   "alice",
		ClientID:  "web-app",
		Provider:  "password",
		Outcome:   audit.OutcomeSuccess,
		RequestID: "req-42",
	}

	cases := []struct {
		name string
		q    audit.Query
		ok   bool
	}{
		{name: "Type match", q: audit.Query{Type: audit.EventLogin}, ok: true},
		{name: "Type miss", q: audit.Query{Type: audit.EventLogout}, ok: false},

		{name: "ActorID match", q: audit.Query{ActorID: "alice"}, ok: true},
		{name: "ActorID miss", q: audit.Query{ActorID: "bob"}, ok: false},

		{name: "ClientID match", q: audit.Query{ClientID: "web-app"}, ok: true},
		{name: "ClientID miss", q: audit.Query{ClientID: "mobile-app"}, ok: false},

		{name: "Provider match", q: audit.Query{Provider: "password"}, ok: true},
		{name: "Provider miss", q: audit.Query{Provider: "phone"}, ok: false},

		{name: "Outcome match", q: audit.Query{Outcome: audit.OutcomeSuccess}, ok: true},
		{name: "Outcome miss", q: audit.Query{Outcome: audit.OutcomeFailure}, ok: false},

		{name: "RequestID match", q: audit.Query{RequestID: "req-42"}, ok: true},
		{name: "RequestID miss", q: audit.Query{RequestID: "req-99"}, ok: false},

		{name: "All fields match",
			q:  audit.Query{Type: audit.EventLogin, ActorID: "alice", ClientID: "web-app", Provider: "password", Outcome: audit.OutcomeSuccess},
			ok: true,
		},
		{name: "One mismatched field disqualifies",
			q:  audit.Query{Type: audit.EventLogin, ActorID: "wrong"},
			ok: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.q.Match(base); got != tc.ok {
				t.Fatalf("Match = %v, want %v", got, tc.ok)
			}
		})
	}
}

func TestQuery_Match_SinceInclusive(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	q := audit.Query{Since: cutoff}

	if !q.Match(&audit.Event{Timestamp: cutoff}) {
		t.Error("Since should be inclusive: event exactly at cutoff should match")
	}
	if !q.Match(&audit.Event{Timestamp: cutoff.Add(time.Second)}) {
		t.Error("event after cutoff should match")
	}
	if q.Match(&audit.Event{Timestamp: cutoff.Add(-time.Second)}) {
		t.Error("event before cutoff should NOT match")
	}
}

func TestQuery_Match_UntilExclusive(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	q := audit.Query{Until: cutoff}

	if q.Match(&audit.Event{Timestamp: cutoff}) {
		t.Error("Until should be exclusive: event exactly at cutoff should NOT match")
	}
	if q.Match(&audit.Event{Timestamp: cutoff.Add(time.Second)}) {
		t.Error("event after cutoff should NOT match")
	}
	if !q.Match(&audit.Event{Timestamp: cutoff.Add(-time.Second)}) {
		t.Error("event before cutoff should match")
	}
}

func TestQuery_Match_ZeroTimeMeansNoBound(t *testing.T) {
	t.Parallel()
	q := audit.Query{} // both Since and Until zero
	if !q.Match(&audit.Event{Timestamp: time.Unix(0, 0)}) {
		t.Error("epoch event should match when no bounds set")
	}
	if !q.Match(&audit.Event{Timestamp: time.Now().Add(100 * time.Hour)}) {
		t.Error("future event should match when no bounds set")
	}
}

func TestQuery_NormalizedLimit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int
		want int
	}{
		{in: 0, want: audit.DefaultQueryLimit},
		{in: -5, want: audit.DefaultQueryLimit},
		{in: 1, want: 1},
		{in: 50, want: 50},
		{in: audit.MaxQueryLimit, want: audit.MaxQueryLimit},
		{in: audit.MaxQueryLimit + 1, want: audit.MaxQueryLimit},
		{in: 10_000_000, want: audit.MaxQueryLimit},
	}
	for _, tc := range cases {
		q := audit.Query{Limit: tc.in}
		if got := q.NormalizedLimit(); got != tc.want {
			t.Errorf("NormalizedLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
