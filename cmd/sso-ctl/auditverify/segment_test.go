package auditverify

// Boundary-anchored segment verification tests (--anchor-hash; requirements
// v2 §6 AC-1..AC-10, failure contract F1-F13).
//
// Byte-stability rules (same convention as checkpoint_test.go): Recorder
// stamps wall-clock timestamps, so hashes are NOT byte-stable across runs.
// Expected lines are built from fixtures or pinned as stable substrings.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// midChainWindow returns events[start:end] of an n-event chain (chain
// order) plus the boundary anchor: the Hash of the last EXCLUDED event —
// exactly what an auditexport bundle's boundary_prev_hash / a relayed
// batch's first-event PrevHash carries.
func midChainWindow(t *testing.T, n, start, end int) ([]*audit.Event, string) {
	t.Helper()
	if start < 0 || end > n || start >= end {
		t.Fatalf("midChainWindow: invalid window [%d,%d) of %d events", start, end, n)
	}
	events := chainedEvents(t, n)
	anchor := ""
	if start > 0 {
		anchor = events[start-1].Hash
	}
	return events[start:end], anchor
}

// newestFirst reverses a chain-order slice into the API/relay delivery
// shape (newest first).
func newestFirst(events []*audit.Event) []*audit.Event {
	reversed := make([]*audit.Event, len(events))
	for i, e := range events {
		reversed[len(events)-1-i] = e
	}
	return reversed
}

// ---------------------------------------------------------------------------
// AC-1 (T-2 #1): mid-chain segment + correct anchor -> 0.

func TestRun_Anchor_MidChainWindow(t *testing.T) {
	window, anchor := midChainWindow(t, 6, 2, 5)
	code, out, errOut := runVerify(t, "--from-file", writeEventsFile(t, window), "--anchor-hash", anchor)
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	want := fmt.Sprintf("segment verified: 3 event(s), anchored=%s, head=%s", anchor, window[len(window)-1].Hash)
	if out != want {
		t.Errorf("stdout:\n got %q\nwant %q", out, want)
	}
	if errOut != "" {
		t.Errorf("stderr = %q; want empty", errOut)
	}
}

// ---------------------------------------------------------------------------
// AC-2 (T-2 #2): same segment without an anchor -> 1, fail-closed at
// index 0 with the chainer's honest break report.

func TestRun_Anchor_MissingAnchorFailsClosed(t *testing.T) {
	window, _ := midChainWindow(t, 6, 2, 5)
	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, window))
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.HasPrefix(errOut, "chain BROKEN: ") || !strings.Contains(errOut, "chain break at index 0") {
		t.Errorf("stderr %q; want chain BROKEN with chain break at index 0", errOut)
	}
}

// ---------------------------------------------------------------------------
// AC-3 (T-2 #3): first-event PrevHash != supplied anchor -> 1; the
// `expected %q` token proves the anchor reached the chainer.

func TestRun_Anchor_WrongAnchor(t *testing.T) {
	window, _ := midChainWindow(t, 6, 2, 5)
	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, window), "--anchor-hash", "deadbeef")
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, `expected "deadbeef"`) {
		t.Errorf("stderr %q; want expected \"deadbeef\"", errOut)
	}
}

// ---------------------------------------------------------------------------
// AC-4 (addition): newest-first JSON of the window + correct anchor -> 0
// (R2 case b: structural reversal before a single verification run).

func TestRun_Anchor_NewestFirstFile(t *testing.T) {
	window, anchor := midChainWindow(t, 6, 2, 5)
	code, out, _ := runVerify(t, "--from-file", writeEventsFile(t, newestFirst(window)), "--anchor-hash", anchor)
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	if !strings.HasPrefix(out, "segment verified:") {
		t.Errorf("stdout %q; want segment verified:", out)
	}
}

// ---------------------------------------------------------------------------
// AC-5 (addition): URL-window — httptest pages a newest-first mid-chain
// slice; --from-url + --anchor-hash -> 0 (R2 after URL paging + reverse).

func TestRun_Anchor_URLWindow(t *testing.T) {
	window, anchor := midChainWindow(t, 6, 2, 5)
	srv := urlServer(t, window)
	code, out, _ := runVerify(t, "--from-url", srv.URL, "--bearer", "t", "--anchor-hash", anchor)
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	if !strings.HasPrefix(out, "segment verified:") {
		t.Errorf("stdout %q; want segment verified:", out)
	}
}

// ---------------------------------------------------------------------------
// AC-6 (T-2 #5): relay-shaped batch — a mid-chain slice is the shape a
// durable-outbox relay delivers (commerce.OutboxEvent carries no
// PrevHash/Hash; the batch's first-event PrevHash IS the boundary anchor).
// With the anchor -> 0; without -> 1.

func TestRun_Anchor_RelayShapedBatch(t *testing.T) {
	batch, anchor := midChainWindow(t, 6, 2, 5)
	code, out, _ := runVerify(t, "--from-file", writeEventsFile(t, batch), "--anchor-hash", anchor)
	if code != 0 {
		t.Fatalf("with anchor: exit = %d; want 0", code)
	}
	if !strings.HasPrefix(out, "segment verified:") {
		t.Errorf("with anchor stdout %q; want segment verified:", out)
	}

	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, batch))
	if code != 1 {
		t.Fatalf("without anchor: exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, "chain break at index 0") {
		t.Errorf("without anchor stderr %q; want chain break at index 0", errOut)
	}
}

// ---------------------------------------------------------------------------
// AC-7 (T-2 #4): --limit truncation never asserts the prefix head is the
// chain tip — anchored and unanchored rows both exit 1 with the honest
// prefix report (R7; the false-tip defect fix).

func TestRun_Anchor_LimitTruncationHonest(t *testing.T) {
	window, anchor := midChainWindow(t, 6, 2, 5) // 3 events, truncated to 2
	code, out, _ := runVerify(t, "--from-file", writeEventsFile(t, window), "--anchor-hash", anchor, "--limit", "2")
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(out, "prefix verified: 2 event(s) — truncated by --limit 2;") ||
		!strings.Contains(out, "is not the full chain") {
		t.Errorf("stdout %q; want honest prefix report", out)
	}
	if strings.Contains(out, "segment verified:") || strings.Contains(out, "chain verified:") {
		t.Errorf("stdout %q; must not claim the prefix head is a verified tip", out)
	}
}

func TestRun_LimitTruncationHonestUnanchored(t *testing.T) {
	events := chainedEvents(t, 5)
	code, out, _ := runVerify(t, "--from-file", writeEventsFile(t, events), "--limit", "3")
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(out, "prefix verified: 3 event(s) — truncated by --limit 3;") ||
		!strings.Contains(out, "is not the full chain") {
		t.Errorf("stdout %q; want honest prefix report", out)
	}
	if strings.Contains(out, "chain verified:") {
		t.Errorf("stdout %q; must not assert the prefix head is the chain tip", out)
	}
}

// --limit 0 is the migration path for window-complete verification: no
// truncation, exit 0 with the anchored segment report.

func TestRun_Anchor_LimitZeroFullWindow(t *testing.T) {
	window, anchor := midChainWindow(t, 6, 2, 5)
	code, out, _ := runVerify(t, "--from-file", writeEventsFile(t, window), "--anchor-hash", anchor, "--limit", "0")
	if code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	if !strings.HasPrefix(out, "segment verified:") {
		t.Errorf("stdout %q; want segment verified:", out)
	}
}

// ---------------------------------------------------------------------------
// AC-8 (addition): misuse exits 2 through checkMisuse's return-code path.

func TestRun_Anchor_EmptyValueMisuse(t *testing.T) {
	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, chainedEvents(t, 3)), "--anchor-hash", "")
	if code != 2 {
		t.Fatalf("exit = %d; want 2 (CLI misuse)", code)
	}
	if !strings.Contains(errOut, "--anchor-hash requires a non-empty value") ||
		!strings.Contains(errOut, "Usage:") {
		t.Errorf("stderr %q; want misuse diagnostic + usage banner", errOut)
	}
}

func TestRun_Anchor_CheckpointMutualExclusion(t *testing.T) {
	events := chainedEvents(t, 3)
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	cp := signedCheckpoint(t, signer, 7, events[len(events)-1].Hash)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, events), "--anchor-hash", "x", "--checkpoint", cpPath)
	if code != 2 {
		t.Fatalf("exit = %d; want 2 (CLI misuse)", code)
	}
	if !strings.Contains(errOut, "--anchor-hash and --checkpoint are mutually exclusive") ||
		!strings.Contains(errOut, "Usage:") {
		t.Errorf("stderr %q; want mutual-exclusion diagnostic + usage banner", errOut)
	}
}

// ---------------------------------------------------------------------------
// AC-9 (addition): empty set — anchored fails closed (R6), unanchored
// keeps the legacy byte-identical row (R4).

func TestRun_Anchor_EmptySegment(t *testing.T) {
	emptyPath := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runVerify(t, "--from-file", emptyPath, "--anchor-hash", "anchor-value")
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	want := `cannot verify an empty segment against anchor "anchor-value"`
	if errOut != want {
		t.Errorf("stderr:\n got %q\nwant %q", errOut, want)
	}
}

// ---------------------------------------------------------------------------
// AC-10 (addition): regression — a full chain is genesis-anchored: its
// first event has PrevHash "" so no non-empty anchor matches (genesis
// anchoring is expressed by OMITTING the flag; R1 semantics).

func TestRun_Anchor_FullChainNotAnchorable(t *testing.T) {
	events := chainedEvents(t, 3)
	code, _, errOut := runVerify(t, "--from-file", writeEventsFile(t, events), "--anchor-hash", "deadbeef")
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(errOut, `expected "deadbeef"`) {
		t.Errorf("stderr %q; want expected \"deadbeef\"", errOut)
	}
}

// ---------------------------------------------------------------------------
// normalizeSegmentOrder unit coverage (R2 cases a/b/c + single event).

func TestNormalizeSegmentOrder(t *testing.T) {
	events := chainedEvents(t, 4) // PrevHash chain: "", h0, h1, h2
	anchor := events[0].Hash

	// Case (a): anchor at [0] keeps chain order.
	seg := append([]*audit.Event(nil), events[1:]...)
	normalizeSegmentOrder(seg, anchor)
	if seg[0] != events[1] {
		t.Error("case (a): order changed; want chain order kept")
	}

	// Case (b): anchor at [len-1] means newest-first; reversed.
	seg = newestFirst(events[1:])
	normalizeSegmentOrder(seg, anchor)
	if seg[0] != events[1] || seg[len(seg)-1] != events[len(events)-1] {
		t.Error("case (b): want reversal into chain order")
	}

	// Case (c): anchor nowhere; order untouched (verification then fails
	// closed at index 0 with the chainer's honest report).
	seg = append([]*audit.Event(nil), events[1:]...)
	normalizeSegmentOrder(seg, "zzz")
	if seg[0] != events[1] {
		t.Error("case (c): order changed; want untouched")
	}
	if err := audit.VerifyChainSegment(seg, "zzz"); err == nil {
		t.Error("case (c): verification passed; want fail-closed chain break")
	}

	// Single event carrying the anchor is case (a) and verifies.
	one := []*audit.Event{events[2]}
	normalizeSegmentOrder(one, events[1].Hash)
	if err := audit.VerifyChainSegment(one, events[1].Hash); err != nil {
		t.Errorf("single anchored event: %v", err)
	}
}
