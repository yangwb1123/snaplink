package memory

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenusage"
)

// at builds a time.Time at the given UTC minute (seconds/sub-second vary to
// prove BucketMinute truncation, not just equal inputs) within test-year
// 2026, month July, day 1.
func at(hour, minute, second int) time.Time {
	return time.Date(2026, time.July, 1, hour, minute, second, 0, time.UTC)
}

func recordEvent(t *testing.T, s *Store, clientID string, kind tokenusage.Kind, endpoint tokenusage.Endpoint, when time.Time) {
	t.Helper()
	if err := s.Record(context.Background(), tokenusage.Event{
		ClientID: clientID,
		Kind:     kind,
		Endpoint: endpoint,
		At:       when,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

// TestStore_BucketsByMinuteClientKindEndpoint proves the bucketing math: two
// events landing in the SAME UTC minute (different seconds) fold into one
// bucket with Count=2; a different minute, client, kind, or endpoint opens
// a distinct bucket. This is the aggregation the whole telemetry design
// depends on to avoid a write-per-event blowup.
func TestStore_BucketsByMinuteClientKindEndpoint(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Two events in the same minute (different seconds) — one bucket, count 2.
	recordEvent(t, s, "client-a", tokenusage.KindAccess, tokenusage.EndpointToken, at(10, 0, 0))
	recordEvent(t, s, "client-a", tokenusage.KindAccess, tokenusage.EndpointToken, at(10, 0, 59))
	// Next minute — a second bucket.
	recordEvent(t, s, "client-a", tokenusage.KindAccess, tokenusage.EndpointToken, at(10, 1, 0))
	// Different client — a third bucket, same minute as the first pair.
	recordEvent(t, s, "client-b", tokenusage.KindAccess, tokenusage.EndpointToken, at(10, 0, 30))
	// Different kind — a fourth bucket.
	recordEvent(t, s, "client-a", tokenusage.KindRefresh, tokenusage.EndpointToken, at(10, 0, 15))
	// Different endpoint — a fifth bucket.
	recordEvent(t, s, "client-a", tokenusage.KindAccess, tokenusage.EndpointIntrospect, at(10, 0, 45))

	buckets, err := s.Query(ctx, tokenusage.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(buckets) != 5 {
		t.Fatalf("len(buckets) = %d, want 5: %+v", len(buckets), buckets)
	}

	var gotFirstMinute int64
	for _, b := range buckets {
		if b.ClientID == "client-a" && b.Kind == tokenusage.KindAccess &&
			b.Endpoint == tokenusage.EndpointToken && b.Minute.Equal(tokenusage.BucketMinute(at(10, 0, 0))) {
			gotFirstMinute = b.Count
		}
	}
	if gotFirstMinute != 2 {
		t.Errorf("client-a/access/token @10:00 count = %d, want 2 (both same-minute events folded)", gotFirstMinute)
	}
}

// TestStore_EvictsOldestOnCap proves the bounded-cardinality contract: once
// the store holds max distinct buckets, the NEXT new bucket evicts the
// oldest-created one rather than growing unbounded — usage telemetry is a
// rolling window, not an archive.
func TestStore_EvictsOldestOnCap(t *testing.T) {
	s := New(WithMaxBuckets(3))
	ctx := context.Background()

	// Three distinct buckets (different minutes) fill the store to capacity.
	recordEvent(t, s, "c", tokenusage.KindAccess, tokenusage.EndpointToken, at(9, 0, 0))
	recordEvent(t, s, "c", tokenusage.KindAccess, tokenusage.EndpointToken, at(9, 1, 0))
	recordEvent(t, s, "c", tokenusage.KindAccess, tokenusage.EndpointToken, at(9, 2, 0))
	if got := s.TrackedBuckets(); got != 3 {
		t.Fatalf("TrackedBuckets = %d, want 3", got)
	}

	// A fourth DISTINCT bucket must evict the oldest (9:00), not grow past cap.
	recordEvent(t, s, "c", tokenusage.KindAccess, tokenusage.EndpointToken, at(9, 3, 0))
	if got := s.TrackedBuckets(); got != 3 {
		t.Fatalf("TrackedBuckets after eviction = %d, want 3 (cap held)", got)
	}

	buckets, err := s.Query(ctx, tokenusage.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, b := range buckets {
		if b.Minute.Equal(tokenusage.BucketMinute(at(9, 0, 0))) {
			t.Fatalf("oldest bucket (9:00) survived eviction: %+v", buckets)
		}
	}

	// Re-recording an EXISTING (already-tracked) bucket must NOT evict —
	// only a genuinely NEW bucket key consumes a capacity slot.
	recordEvent(t, s, "c", tokenusage.KindAccess, tokenusage.EndpointToken, at(9, 3, 30))
	if got := s.TrackedBuckets(); got != 3 {
		t.Fatalf("TrackedBuckets after re-recording an existing bucket = %d, want 3", got)
	}
}

// TestStore_QueryFiltersByClientAndHalfOpenWindow proves ClientID filtering
// and the [Since, Until) half-open window contract — a bucket exactly AT
// Until must be excluded so adjacent query windows never double-count.
func TestStore_QueryFiltersByClientAndHalfOpenWindow(t *testing.T) {
	s := New()
	ctx := context.Background()
	recordEvent(t, s, "a", tokenusage.KindAccess, tokenusage.EndpointToken, at(8, 0, 0))
	recordEvent(t, s, "b", tokenusage.KindAccess, tokenusage.EndpointToken, at(8, 0, 0))
	recordEvent(t, s, "a", tokenusage.KindAccess, tokenusage.EndpointToken, at(8, 1, 0))
	recordEvent(t, s, "a", tokenusage.KindAccess, tokenusage.EndpointToken, at(8, 2, 0))

	buckets, err := s.Query(ctx, tokenusage.Query{ClientID: "a"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(buckets) != 3 {
		t.Fatalf("client-filtered buckets = %d, want 3", len(buckets))
	}

	// Window [8:00, 8:02) must include 8:00 and 8:01 but EXCLUDE 8:02 (the
	// Until boundary itself).
	windowed, err := s.Query(ctx, tokenusage.Query{
		ClientID: "a",
		Since:    at(8, 0, 0),
		Until:    at(8, 2, 0),
	})
	if err != nil {
		t.Fatalf("Query windowed: %v", err)
	}
	if len(windowed) != 2 {
		t.Fatalf("windowed buckets = %d, want 2 (Until exclusive): %+v", len(windowed), windowed)
	}
	for _, b := range windowed {
		if b.Minute.Equal(tokenusage.BucketMinute(at(8, 2, 0))) {
			t.Fatalf("Until-boundary bucket leaked into a half-open window: %+v", b)
		}
	}
}
