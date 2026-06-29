package idp

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func mkRow(spEntityID, sloURL, nameID string) SAMLSPSession {
	return SAMLSPSession{
		SPEntityID: spEntityID,
		SPClientID: spEntityID + "-client",
		SPSLOUrl:   sloURL,
		SPBinding:  BindingRedirect,
		NameID:     nameID,
	}
}

// TestSessionIndex_RecordListRemove covers the core CRUD: record two SPs for a
// subject, list them back, remove one, remove all.
func TestSessionIndex_RecordListRemove(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(0, 0)
	ctx := context.Background()
	const sub = "alice@example.com"

	if err := idx.Record(ctx, sub, mkRow("sp-a", "https://a/slo", sub)); err != nil {
		t.Fatalf("record a: %v", err)
	}
	if err := idx.Record(ctx, sub, mkRow("sp-b", "https://b/slo", sub)); err != nil {
		t.Fatalf("record b: %v", err)
	}

	rows, err := idx.ListBySubject(ctx, sub)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(rows), rows)
	}
	// Order is insertion order (a then b).
	if rows[0].SPEntityID != "sp-a" || rows[1].SPEntityID != "sp-b" {
		t.Fatalf("rows out of order: %+v", rows)
	}
	if rows[0].SPSLOUrl != "https://a/slo" {
		t.Fatalf("sp-a SLO URL = %q", rows[0].SPSLOUrl)
	}

	// Remove one.
	if err := idx.Remove(ctx, sub, "sp-a"); err != nil {
		t.Fatalf("remove a: %v", err)
	}
	rows, _ = idx.ListBySubject(ctx, sub)
	if len(rows) != 1 || rows[0].SPEntityID != "sp-b" {
		t.Fatalf("after remove a, rows = %+v", rows)
	}

	// RemoveAll drops the subject.
	if err := idx.RemoveAll(ctx, sub); err != nil {
		t.Fatalf("remove all: %v", err)
	}
	rows, _ = idx.ListBySubject(ctx, sub)
	if len(rows) != 0 {
		t.Fatalf("after RemoveAll, rows = %+v", rows)
	}
	if idx.subjectCount() != 0 {
		t.Fatalf("subjectCount = %d, want 0 after RemoveAll", idx.subjectCount())
	}
}

// TestSessionIndex_ReRecordUpdatesInPlace proves recording the same
// (subject, SPEntityID) again UPDATES the row (refreshed SLO URL) rather than
// duplicating it — so the fan-out never double-sends to one SP.
func TestSessionIndex_ReRecordUpdatesInPlace(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(0, 0)
	ctx := context.Background()
	const sub = "bob@example.com"

	_ = idx.Record(ctx, sub, mkRow("sp-a", "https://a/slo-old", sub))
	_ = idx.Record(ctx, sub, mkRow("sp-a", "https://a/slo-new", sub))

	rows, _ := idx.ListBySubject(ctx, sub)
	if len(rows) != 1 {
		t.Fatalf("re-record duplicated the SP row: %+v", rows)
	}
	if rows[0].SPSLOUrl != "https://a/slo-new" {
		t.Fatalf("re-record did not refresh the SLO URL: %q", rows[0].SPSLOUrl)
	}
}

// TestSessionIndex_RemoveLastSPDropsSubject proves removing a subject's last SP
// row drops the (empty) subject entry from the LRU.
func TestSessionIndex_RemoveLastSPDropsSubject(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(0, 0)
	ctx := context.Background()
	const sub = "carol@example.com"

	_ = idx.Record(ctx, sub, mkRow("sp-a", "https://a/slo", sub))
	_ = idx.Remove(ctx, sub, "sp-a")
	if idx.subjectCount() != 0 {
		t.Fatalf("empty subject lingered in LRU: subjectCount = %d", idx.subjectCount())
	}
}

// TestSessionIndex_UnknownSubject covers list/remove on an unknown subject.
func TestSessionIndex_UnknownSubject(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(0, 0)
	ctx := context.Background()
	rows, err := idx.ListBySubject(ctx, "nobody")
	if err != nil || rows != nil {
		t.Fatalf("unknown subject: rows=%+v err=%v", rows, err)
	}
	if err := idx.Remove(ctx, "nobody", "sp-x"); err != nil {
		t.Fatalf("remove unknown: %v", err)
	}
	if err := idx.RemoveAll(ctx, "nobody"); err != nil {
		t.Fatalf("removeall unknown: %v", err)
	}
}

// TestSessionIndex_BlankIgnored proves a blank subject or blank SP entity id is
// ignored (no row, no error) — a degenerate assertion can't pollute the index.
func TestSessionIndex_BlankIgnored(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(0, 0)
	ctx := context.Background()
	_ = idx.Record(ctx, "", mkRow("sp-a", "https://a/slo", ""))
	_ = idx.Record(ctx, "sub", mkRow("", "https://a/slo", "sub"))
	if idx.subjectCount() != 0 {
		t.Fatalf("blank record was stored: subjectCount = %d", idx.subjectCount())
	}
}

// TestSessionIndex_SubjectCapEvictsOldest proves the subject LRU is bounded: past
// the subject cap the least-recently-recorded subject is evicted whole.
func TestSessionIndex_SubjectCapEvictsOldest(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(3, 0) // cap 3 subjects
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		sub := fmt.Sprintf("sub-%d", i)
		_ = idx.Record(ctx, sub, mkRow("sp-a", "https://a/slo", sub))
	}
	if idx.subjectCount() != 3 {
		t.Fatalf("subjectCount = %d, want 3 (cap enforced)", idx.subjectCount())
	}
	// The two oldest (sub-0, sub-1) were evicted; the three newest remain.
	for i := 0; i < 2; i++ {
		rows, _ := idx.ListBySubject(ctx, fmt.Sprintf("sub-%d", i))
		if len(rows) != 0 {
			t.Fatalf("evicted subject sub-%d still present: %+v", i, rows)
		}
	}
	for i := 2; i < 5; i++ {
		rows, _ := idx.ListBySubject(ctx, fmt.Sprintf("sub-%d", i))
		if len(rows) != 1 {
			t.Fatalf("surviving subject sub-%d missing: %+v", i, rows)
		}
	}
}

// TestSessionIndex_RecordTouchesRecency proves recording a subject again moves it
// to the most-recently-used end (so it survives eviction over a stale subject).
func TestSessionIndex_RecordTouchesRecency(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(2, 0) // cap 2 subjects
	ctx := context.Background()

	_ = idx.Record(ctx, "old", mkRow("sp-a", "https://a/slo", "old"))
	_ = idx.Record(ctx, "mid", mkRow("sp-a", "https://a/slo", "mid"))
	// Touch "old" — now "mid" is the LRU.
	_ = idx.Record(ctx, "old", mkRow("sp-b", "https://b/slo", "old"))
	// Insert a third subject → evicts the LRU ("mid").
	_ = idx.Record(ctx, "new", mkRow("sp-a", "https://a/slo", "new"))

	if rows, _ := idx.ListBySubject(ctx, "mid"); len(rows) != 0 {
		t.Fatalf("'mid' should have been evicted as LRU: %+v", rows)
	}
	if rows, _ := idx.ListBySubject(ctx, "old"); len(rows) != 2 {
		t.Fatalf("'old' should survive (touched): %+v", rows)
	}
	if rows, _ := idx.ListBySubject(ctx, "new"); len(rows) != 1 {
		t.Fatalf("'new' should be present: %+v", rows)
	}
}

// TestSessionIndex_SPCapEvictsOldest proves the per-subject SP list is bounded.
func TestSessionIndex_SPCapEvictsOldest(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(0, 3) // cap 3 SPs per subject
	ctx := context.Background()
	const sub = "dave@example.com"

	for i := 0; i < 5; i++ {
		_ = idx.Record(ctx, sub, mkRow(fmt.Sprintf("sp-%d", i), "https://x/slo", sub))
	}
	rows, _ := idx.ListBySubject(ctx, sub)
	if len(rows) != 3 {
		t.Fatalf("per-subject SP cap not enforced: %d rows", len(rows))
	}
	// The two oldest SPs (sp-0, sp-1) evicted; sp-2..sp-4 remain.
	got := map[string]bool{}
	for _, r := range rows {
		got[r.SPEntityID] = true
	}
	if got["sp-0"] || got["sp-1"] {
		t.Fatalf("oldest SPs not evicted: %+v", rows)
	}
	if !got["sp-2"] || !got["sp-3"] || !got["sp-4"] {
		t.Fatalf("newest SPs missing: %+v", rows)
	}
}

// TestSessionIndex_ListReturnsCopy proves the returned slice is a copy — mutating
// it does not corrupt the index.
func TestSessionIndex_ListReturnsCopy(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(0, 0)
	ctx := context.Background()
	const sub = "erin@example.com"
	_ = idx.Record(ctx, sub, mkRow("sp-a", "https://a/slo", sub))

	rows, _ := idx.ListBySubject(ctx, sub)
	rows[0].SPSLOUrl = "https://evil/slo" // mutate the copy

	again, _ := idx.ListBySubject(ctx, sub)
	if again[0].SPSLOUrl != "https://a/slo" {
		t.Fatalf("ListBySubject leaked a mutable reference: %q", again[0].SPSLOUrl)
	}
}

// TestSessionIndex_Concurrent hammers the index from many goroutines (run with
// -race) to prove the locking is sound under concurrent Record/List/Remove.
func TestSessionIndex_Concurrent(t *testing.T) {
	t.Parallel()
	idx := NewMemorySessionIndex(0, 0)
	ctx := context.Background()

	var wg sync.WaitGroup
	const workers = 16
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				sub := fmt.Sprintf("sub-%d", (w+i)%32)
				sp := fmt.Sprintf("sp-%d", i%8)
				_ = idx.Record(ctx, sub, mkRow(sp, "https://x/slo", sub))
				_, _ = idx.ListBySubject(ctx, sub)
				if i%5 == 0 {
					_ = idx.Remove(ctx, sub, sp)
				}
				if i%50 == 0 {
					_ = idx.RemoveAll(ctx, sub)
				}
			}
		}(w)
	}
	wg.Wait()
	// No assertion beyond "did not race / deadlock"; the index stays bounded.
	if idx.subjectCount() > 32 {
		t.Fatalf("subjectCount = %d exceeds the 32 distinct subjects used", idx.subjectCount())
	}
}
