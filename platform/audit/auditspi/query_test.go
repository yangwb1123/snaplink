package auditspi

import (
	"testing"
	"time"
)

// TestQuery_Match_Wildcards confirms the zero-value Query (all fields empty)
// matches any event — the documented "empty fields are wildcards" contract
// that every in-memory / SQL-less Sink leans on for unfiltered listing.
func TestQuery_Match_Wildcards(t *testing.T) {
	t.Parallel()
	e := &Event{Type: EventLogin, Outcome: OutcomeSuccess, ActorID: "u1", ClientID: "c1",
		TenantID: "t1", Provider: "password", RequestID: "r1", TraceID: "tr1",
		Timestamp: time.Now()}
	if !(Query{}).Match(e) {
		t.Fatal("zero-value Query must match every event")
	}
}

// TestQuery_Match_EnumsAndIdentifiers is table-driven over each single-field
// filter in isolation, proving both the match and the mismatch side of each
// — a Sink's in-memory query path (or any backend reusing Match) is only as
// safe as this per-field boundary.
func TestQuery_Match_EnumsAndIdentifiers(t *testing.T) {
	t.Parallel()
	base := &Event{
		Type: EventLogin, Outcome: OutcomeSuccess,
		ActorID: "user-1", ClientID: "client-1", TenantID: "tenant-1",
		Provider: "password", RequestID: "req-1", TraceID: "trace-1",
	}

	tests := []struct {
		name  string
		q     Query
		match bool
	}{
		{"type match", Query{Type: EventLogin}, true},
		{"type mismatch", Query{Type: EventLogout}, false},
		{"outcome match", Query{Outcome: OutcomeSuccess}, true},
		{"outcome mismatch", Query{Outcome: OutcomeFailure}, false},
		{"actor match", Query{ActorID: "user-1"}, true},
		{"actor mismatch", Query{ActorID: "user-2"}, false},
		{"client match", Query{ClientID: "client-1"}, true},
		{"client mismatch", Query{ClientID: "client-2"}, false},
		{"tenant match", Query{TenantID: "tenant-1"}, true},
		{"tenant mismatch", Query{TenantID: "tenant-2"}, false},
		{"provider match", Query{Provider: "password"}, true},
		{"provider mismatch", Query{Provider: "webauthn"}, false},
		{"request id match", Query{RequestID: "req-1"}, true},
		{"request id mismatch", Query{RequestID: "req-2"}, false},
		{"trace id match", Query{TraceID: "trace-1"}, true},
		{"trace id mismatch", Query{TraceID: "trace-2"}, false},
		{"combined all match", Query{Type: EventLogin, Outcome: OutcomeSuccess, ActorID: "user-1", ClientID: "client-1"}, true},
		{"combined one mismatch fails whole", Query{Type: EventLogin, ActorID: "user-2"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.q.Match(base); got != tt.match {
				t.Errorf("Match() = %v, want %v (query=%+v)", got, tt.match, tt.q)
			}
		})
	}
}

// TestQuery_Match_TimeRange pins the half-open range semantics documented on
// Query: Since is inclusive, Until is exclusive. Off-by-one here would let an
// event leak one instant across an audit query boundary or silently drop the
// event exactly at Since.
func TestQuery_Match_TimeRange(t *testing.T) {
	t.Parallel()
	mid := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e := &Event{Timestamp: mid}

	tests := []struct {
		name  string
		since time.Time
		until time.Time
		match bool
	}{
		{"no bounds", time.Time{}, time.Time{}, true},
		{"since exactly at timestamp is inclusive", mid, time.Time{}, true},
		{"since after timestamp excludes", mid.Add(time.Second), time.Time{}, false},
		{"since before timestamp includes", mid.Add(-time.Second), time.Time{}, true},
		{"until exactly at timestamp is exclusive", time.Time{}, mid, false},
		{"until after timestamp includes", time.Time{}, mid.Add(time.Second), true},
		{"until before timestamp excludes", time.Time{}, mid.Add(-time.Second), false},
		{"inside half-open window", mid.Add(-time.Second), mid.Add(time.Second), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			q := Query{Since: tt.since, Until: tt.until}
			if got := q.Match(e); got != tt.match {
				t.Errorf("Match() = %v, want %v (since=%v until=%v)", got, tt.match, tt.since, tt.until)
			}
		})
	}
}

// TestQuery_NormalizedLimit pins the clamp-and-default contract: unset or
// negative falls back to DefaultQueryLimit, oversized is capped at
// MaxQueryLimit, in-range values pass through unchanged. Every Sink that
// bounds memory/response size for Query delegates to this helper instead of
// re-implementing the clamp.
func TestQuery_NormalizedLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{"zero defaults", 0, DefaultQueryLimit},
		{"negative defaults", -5, DefaultQueryLimit},
		{"within range passes through", 50, 50},
		{"exactly default", DefaultQueryLimit, DefaultQueryLimit},
		{"exactly max passes through", MaxQueryLimit, MaxQueryLimit},
		{"over max is capped", MaxQueryLimit + 1, MaxQueryLimit},
		{"far over max is capped", MaxQueryLimit * 10, MaxQueryLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			q := Query{Limit: tt.limit}
			if got := q.NormalizedLimit(); got != tt.want {
				t.Errorf("NormalizedLimit() = %d, want %d", got, tt.want)
			}
		})
	}
}
