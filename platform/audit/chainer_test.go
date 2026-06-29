package audit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

// recordN drives n events through a chain-enabled recorder + memory
// sink and returns the resulting events in OLDEST-FIRST chain order
// so tests can hand directly to VerifyChain.
func recordN(t *testing.T, n int) []*audit.Event {
	t.Helper()
	sink := audit.NewMemorySink(n + 1)
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		return time.Unix(1700000000, 0).UTC()
	}))
	for i := 0; i < n; i++ {
		r.Record(context.Background(), &audit.Event{
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
			ActorID: "user",
		})
	}
	// MemorySink returns newest-first; reverse for chain order.
	newestFirst, err := sink.Query(context.Background(), audit.Query{Limit: n + 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	oldestFirst := make([]*audit.Event, len(newestFirst))
	for i, e := range newestFirst {
		oldestFirst[len(newestFirst)-1-i] = e
	}
	return oldestFirst
}

func TestHashChain_GenesisAndContinuity(t *testing.T) {
	events := recordN(t, 5)
	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}
	if events[0].PrevHash != "" {
		t.Errorf("genesis PrevHash = %q, want \"\"", events[0].PrevHash)
	}
	for i := 1; i < len(events); i++ {
		if events[i].PrevHash != events[i-1].Hash {
			t.Errorf("event %d PrevHash = %q, want %q (continuity broken)",
				i, events[i].PrevHash, events[i-1].Hash)
		}
	}
}

func TestHashChain_HashFieldNonEmpty(t *testing.T) {
	events := recordN(t, 3)
	for i, e := range events {
		if len(e.Hash) != 64 {
			t.Errorf("event %d Hash = %q, want 64-hex-char sha256", i, e.Hash)
		}
	}
}

func TestVerifyChain_ValidChainNoError(t *testing.T) {
	events := recordN(t, 5)
	if err := audit.VerifyChain(events); err != nil {
		t.Errorf("VerifyChain on valid chain: %v", err)
	}
}

func TestVerifyChain_EmptyChainIsValid(t *testing.T) {
	// Genesis-only state — no events recorded yet — verifies trivially.
	if err := audit.VerifyChain(nil); err != nil {
		t.Errorf("VerifyChain(nil): %v", err)
	}
	if err := audit.VerifyChain([]*audit.Event{}); err != nil {
		t.Errorf("VerifyChain(empty): %v", err)
	}
}

func TestVerifyChain_DetectsTamperedReason(t *testing.T) {
	events := recordN(t, 5)
	// Mutate the middle event's Reason — its Hash no longer matches.
	events[2].Reason = "tampered"

	err := audit.VerifyChain(events)
	if err == nil {
		t.Fatal("VerifyChain accepted tampered event")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("error message doesn't mention hash mismatch: %v", err)
	}
}

func TestVerifyChain_DetectsRemovedEvent(t *testing.T) {
	events := recordN(t, 5)
	// Drop event[2] — events[3].PrevHash no longer matches events[2's
	// successor]'s Hash.
	tampered := append([]*audit.Event{}, events[:2]...)
	tampered = append(tampered, events[3:]...)

	err := audit.VerifyChain(tampered)
	if err == nil {
		t.Fatal("VerifyChain accepted chain with removed event")
	}
	if !strings.Contains(err.Error(), "chain break") {
		t.Errorf("error doesn't mention chain break: %v", err)
	}
}

func TestVerifyChain_DetectsReorderedEvents(t *testing.T) {
	events := recordN(t, 5)
	events[1], events[2] = events[2], events[1]

	err := audit.VerifyChain(events)
	if err == nil {
		t.Fatal("VerifyChain accepted reordered events")
	}
}

func TestVerifyChain_DetectsWrongOrderNewestFirst(t *testing.T) {
	// Easy operator mistake — pass query results directly (newest first)
	// to VerifyChain. The genesis check at index 0 catches it.
	events := recordN(t, 3)
	reversed := make([]*audit.Event, len(events))
	for i, e := range events {
		reversed[len(events)-1-i] = e
	}
	err := audit.VerifyChain(reversed)
	if err == nil {
		t.Fatal("VerifyChain accepted newest-first events as a chain")
	}
	if !strings.Contains(err.Error(), "chain order") {
		t.Errorf("error doesn't nudge toward chain-order: %v", err)
	}
}

func TestHashChain_DisabledByDefault(t *testing.T) {
	// Without WithHashChain, no fields are stamped — zero overhead, no
	// behavior change for callers who don't opt in.
	sink := audit.NewMemorySink(2)
	r := audit.New(sink)
	r.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	got, _ := sink.Query(context.Background(), audit.Query{Limit: 5})
	if len(got) != 1 {
		t.Fatalf("got %d events", len(got))
	}
	if got[0].Hash != "" || got[0].PrevHash != "" {
		t.Errorf("hashes should be empty without WithHashChain: hash=%q prev=%q",
			got[0].Hash, got[0].PrevHash)
	}
}

// TestHashChain_TimezoneStableAcrossDurableReadback guards the false-tamper bug
// on non-UTC hosts: events stamped from a LOCAL-zone clock must still VerifyChain
// after the durable round-trip reconstructs Timestamp as UTC. Without the
// eventHash UTC normalization, VerifyChain reports every event as tampered.
func TestHashChain_TimezoneStableAcrossDurableReadback(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tz db unavailable: %v", err)
	}
	sink := audit.NewMemorySink(8)
	base := time.Unix(1782000000, 123456789).In(loc) // non-UTC offset, like time.Now() on a local host
	n := 0
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		n++
		return base.Add(time.Duration(n) * time.Second)
	}))
	for k := 0; k < 5; k++ {
		r.Record(context.Background(), &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "u"})
	}
	newestFirst, err := sink.Query(context.Background(), audit.Query{Limit: 8})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	events := make([]*audit.Event, len(newestFirst))
	for j, e := range newestFirst {
		cp := *e
		cp.Timestamp = e.Timestamp.UTC() // simulate the durable sink read-back (same instant, UTC)
		events[len(newestFirst)-1-j] = &cp
	}
	if err := audit.VerifyChain(events); err != nil {
		t.Fatalf("chain falsely BROKEN after UTC read-back of locally-stamped events: %v", err)
	}
}

// TestHashChain_StampedTimestampsAreMonotonic guards the chain-order fix: even
// when the wall clock returns decreasing values across records, the stamped
// (persisted) timestamps must be strictly increasing in chain order so the
// durable ORDER BY ts_unix_ns reconstructs the true chain order (not a false break).
func TestHashChain_StampedTimestampsAreMonotonic(t *testing.T) {
	sink := audit.NewMemorySink(8)
	calls := 0
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		calls++
		return time.Unix(1700000000, 0).Add(-time.Duration(calls) * time.Second).UTC() // goes BACKWARD
	}))
	for k := 0; k < 5; k++ {
		r.Record(context.Background(), &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "u"})
	}
	newestFirst, _ := sink.Query(context.Background(), audit.Query{Limit: 8})
	events := make([]*audit.Event, len(newestFirst))
	for j, e := range newestFirst {
		events[len(newestFirst)-1-j] = e
	}
	for i := 1; i < len(events); i++ {
		if !events[i].Timestamp.After(events[i-1].Timestamp) {
			t.Fatalf("stamped ts not strictly increasing at %d: %v <= %v", i, events[i].Timestamp, events[i-1].Timestamp)
		}
	}
}
