// Package sessionindextest hosts the shared idp.SAMLSessionIndex conformance
// suite, run against BOTH the in-memory MemorySessionIndex and the sqlite
// SessionIndex so they're locked to identical observable behavior.
//
// It lives in its OWN package (not the sibling samltest replay suite) because it
// imports github.com/snaplink/sso/saml/idp (for SAMLSPSession): a conformance
// suite that imported idp could not be used from an INTERNAL `package idp` test
// (import cycle). The memory side runs it from an EXTERNAL `package idp_test`
// (which may import idp), the sqlite side from saml/idp/sqlite — neither cycles.
package sessionindextest

import (
	"context"
	"testing"

	samlidp "github.com/snaplink/sso/saml/idp"
)

// SessionIndexConformance exercises every idp.SAMLSessionIndex semantic both the
// memory and sqlite backends MUST agree on. Factory returns a FRESH, EMPTY index
// per subtest.
//
// SCOPE NOTE: it asserts the SHARED contract — Record/ListBySubject/Remove/
// RemoveAll, in-place re-record, insertion order, blank-ignored, unknown-subject
// no-ops, list-returns-a-copy, and the per-subject SP cap (the adversary-facing
// bound both backends keep). It deliberately does NOT assert the subject-LRU
// eviction: that is a MEMORY-only growth bound (a per-replica recency signal a
// shared store can't fairly reproduce); the sqlite peer bounds growth by the
// per-subject cap + RemoveAll + age-pruning instead (documented on the sqlite
// store). Asserting the subject-LRU here would wrongly force the shared backend
// to drop a still-logged-in subject's fan-out rows.
type SessionIndexConformance struct {
	Factory func(t *testing.T) samlidp.SAMLSessionIndex

	// SPsPerSubjectCap is the per-subject SP-row cap the factory's index is built
	// with, so the cap subtest can drive past it deterministically. <=0 skips the
	// cap subtest (a backend that doesn't cap).
	SPsPerSubjectCap int
}

func mkRow(spEntityID, sloURL, nameID string) samlidp.SAMLSPSession {
	return samlidp.SAMLSPSession{
		SPEntityID: spEntityID,
		SPClientID: spEntityID + "-client",
		SPSLOUrl:   sloURL,
		SPBinding:  samlidp.BindingRedirect,
		NameID:     nameID,
	}
}

// Run executes every session-index conformance subtest against the Factory.
func (s SessionIndexConformance) Run(t *testing.T) {
	t.Helper()
	if s.Factory == nil {
		t.Fatal("SessionIndexConformance: Factory required")
	}
	cases := []struct {
		name string
		fn   func(*testing.T, samlidp.SAMLSessionIndex)
	}{
		{"RecordListRemove", testRecordListRemove},
		{"ReRecordUpdatesInPlace", testReRecordUpdatesInPlace},
		{"InsertionOrderPreserved", testInsertionOrderPreserved},
		{"UnknownSubject", testUnknownSubject},
		{"BlankIgnored", testBlankIgnored},
		{"ListReturnsCopy", testListReturnsCopy},
		{"AllFieldsRoundTrip", testAllFieldsRoundTrip},
		{"RemoveAllScopedToSubject", testRemoveAllScopedToSubject},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			idx := s.Factory(t)
			c.fn(t, idx)
		})
	}
	if s.SPsPerSubjectCap > 0 {
		t.Run("PerSubjectSPCapEvictsOldest", func(t *testing.T) {
			idx := s.Factory(t)
			testPerSubjectSPCap(t, idx, s.SPsPerSubjectCap)
		})
	}
}

func testRecordListRemove(t *testing.T, idx samlidp.SAMLSessionIndex) {
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
	if err := idx.Remove(ctx, sub, "sp-a"); err != nil {
		t.Fatalf("remove a: %v", err)
	}
	rows, _ = idx.ListBySubject(ctx, sub)
	if len(rows) != 1 || rows[0].SPEntityID != "sp-b" {
		t.Fatalf("after remove a, rows = %+v", rows)
	}
	if err := idx.RemoveAll(ctx, sub); err != nil {
		t.Fatalf("remove all: %v", err)
	}
	rows, _ = idx.ListBySubject(ctx, sub)
	if len(rows) != 0 {
		t.Fatalf("after RemoveAll, rows = %+v", rows)
	}
}

func testReRecordUpdatesInPlace(t *testing.T, idx samlidp.SAMLSessionIndex) {
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

func testInsertionOrderPreserved(t *testing.T, idx samlidp.SAMLSessionIndex) {
	ctx := context.Background()
	const sub = "carol@example.com"
	for _, sp := range []string{"sp-1", "sp-2", "sp-3"} {
		_ = idx.Record(ctx, sub, mkRow(sp, "https://x/slo", sub))
	}
	rows, _ := idx.ListBySubject(ctx, sub)
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %+v", rows)
	}
	for i, want := range []string{"sp-1", "sp-2", "sp-3"} {
		if rows[i].SPEntityID != want {
			t.Fatalf("row %d = %q, want %q (insertion order): %+v", i, rows[i].SPEntityID, want, rows)
		}
	}
}

func testUnknownSubject(t *testing.T, idx samlidp.SAMLSessionIndex) {
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

func testBlankIgnored(t *testing.T, idx samlidp.SAMLSessionIndex) {
	ctx := context.Background()
	if err := idx.Record(ctx, "", mkRow("sp-a", "https://a/slo", "")); err != nil {
		t.Fatalf("blank subject record errored: %v", err)
	}
	if err := idx.Record(ctx, "sub", mkRow("", "https://a/slo", "sub")); err != nil {
		t.Fatalf("blank SP record errored: %v", err)
	}
	// Neither was stored.
	if rows, _ := idx.ListBySubject(ctx, ""); len(rows) != 0 {
		t.Fatalf("blank subject was stored: %+v", rows)
	}
	if rows, _ := idx.ListBySubject(ctx, "sub"); len(rows) != 0 {
		t.Fatalf("blank SP entity id was stored: %+v", rows)
	}
}

func testListReturnsCopy(t *testing.T, idx samlidp.SAMLSessionIndex) {
	ctx := context.Background()
	const sub = "erin@example.com"
	_ = idx.Record(ctx, sub, mkRow("sp-a", "https://a/slo", sub))
	rows, _ := idx.ListBySubject(ctx, sub)
	rows[0].SPSLOUrl = "https://evil/slo" // mutate the returned slice
	again, _ := idx.ListBySubject(ctx, sub)
	if again[0].SPSLOUrl != "https://a/slo" {
		t.Fatalf("ListBySubject leaked a mutable reference: %q", again[0].SPSLOUrl)
	}
}

func testAllFieldsRoundTrip(t *testing.T, idx samlidp.SAMLSessionIndex) {
	ctx := context.Background()
	const sub = "frank@example.com"
	want := samlidp.SAMLSPSession{
		SPEntityID:   "sp-x",
		SPClientID:   "client-x",
		SPSLOUrl:     "https://x/slo",
		SPBinding:    samlidp.BindingPost,
		SPChannel:    "frontchannel",
		NameID:       sub,
		SessionIndex: "sess-123",
	}
	if err := idx.Record(ctx, sub, want); err != nil {
		t.Fatalf("record: %v", err)
	}
	rows, _ := idx.ListBySubject(ctx, sub)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %+v", rows)
	}
	if rows[0] != want {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", rows[0], want)
	}
}

func testRemoveAllScopedToSubject(t *testing.T, idx samlidp.SAMLSessionIndex) {
	ctx := context.Background()
	_ = idx.Record(ctx, "sub-1", mkRow("sp-a", "https://a/slo", "sub-1"))
	_ = idx.Record(ctx, "sub-2", mkRow("sp-a", "https://a/slo", "sub-2"))
	if err := idx.RemoveAll(ctx, "sub-1"); err != nil {
		t.Fatalf("removeall sub-1: %v", err)
	}
	if rows, _ := idx.ListBySubject(ctx, "sub-1"); len(rows) != 0 {
		t.Fatalf("sub-1 not cleared: %+v", rows)
	}
	if rows, _ := idx.ListBySubject(ctx, "sub-2"); len(rows) != 1 {
		t.Fatalf("RemoveAll leaked into sub-2: %+v", rows)
	}
}

// testPerSubjectSPCap drives past the per-subject SP cap and asserts the OLDEST
// rows were evicted (the newest `cap` survive). Both backends keep this bound.
func testPerSubjectSPCap(t *testing.T, idx samlidp.SAMLSessionIndex, cap int) {
	ctx := context.Background()
	const sub = "dave@example.com"
	total := cap + 3
	for i := 0; i < total; i++ {
		_ = idx.Record(ctx, sub, mkRow(spName(i), "https://x/slo", sub))
	}
	rows, _ := idx.ListBySubject(ctx, sub)
	if len(rows) != cap {
		t.Fatalf("per-subject SP cap not enforced: %d rows, want %d", len(rows), cap)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[r.SPEntityID] = true
	}
	// The first `total-cap` (oldest) must be gone; the last `cap` survive.
	for i := 0; i < total-cap; i++ {
		if got[spName(i)] {
			t.Fatalf("oldest SP %s should have been evicted: %+v", spName(i), rows)
		}
	}
	for i := total - cap; i < total; i++ {
		if !got[spName(i)] {
			t.Fatalf("newest SP %s missing after cap eviction: %+v", spName(i), rows)
		}
	}
}

func spName(i int) string {
	return "sp-" + string(rune('A'+i))
}
