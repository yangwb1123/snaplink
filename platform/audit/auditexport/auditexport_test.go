package auditexport_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/audit/auditexport"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
)

// chainBase is a fixed clock origin; recordChain advances it one hour
// per event so stamped timestamps are strictly increasing (no 1ns
// bump) and time-window filters can land BETWEEN events deterministically.
var chainBase = time.Unix(1700000000, 0).UTC()

func eventTime(i int) time.Time { return chainBase.Add(time.Duration(i) * time.Hour) }

// recordChain drives n hash-chained login events into a MemorySink at
// one-hour spacing and returns the sink for BuildExportBundle to page.
func recordChain(t *testing.T, n int) *audit.MemorySink {
	t.Helper()
	sink := audit.NewMemorySink(n + 1)
	i := 0
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		i++
		return eventTime(i)
	}))
	for k := 0; k < n; k++ {
		r.Record(context.Background(), &audit.Event{
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
			ActorID: "user",
		})
	}
	return sink
}

func TestBuildExportBundle_FullRangeMatchesGenesis(t *testing.T) {
	t.Parallel()
	sink := recordChain(t, 5)
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{})
	if err != nil {
		t.Fatalf("BuildExportBundle: %v", err)
	}
	if b.EventCount != 5 || len(b.Events) != 5 {
		t.Fatalf("EventCount=%d len(Events)=%d, want 5", b.EventCount, len(b.Events))
	}
	if b.BoundaryPrevHash != audit.GenesisHash {
		t.Errorf("BoundaryPrevHash=%q, want genesis (empty)", b.BoundaryPrevHash)
	}
	if !b.Contiguous {
		t.Error("full-range export should be marked Contiguous")
	}
	if b.HeadHash != b.Events[len(b.Events)-1].Hash {
		t.Error("HeadHash must equal the last event's Hash")
	}
	if b.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should be stamped")
	}
	if err := auditexport.VerifyExportBundle(b); err != nil {
		t.Errorf("VerifyExportBundle: %v", err)
	}
	// A full-range export starts at genesis, so the plain chain verifier
	// accepts it too.
	if err := audit.VerifyChain(b.Events); err != nil {
		t.Errorf("VerifyChain on full-range export: %v", err)
	}
}

func TestBuildExportBundle_MidChainSegment(t *testing.T) {
	t.Parallel()
	sink := recordChain(t, 6)
	// A window that begins between the 3rd and 4th event → events 4,5,6.
	since := eventTime(3).Add(30 * time.Minute)
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{Since: since})
	if err != nil {
		t.Fatalf("BuildExportBundle: %v", err)
	}
	if b.EventCount != 3 {
		t.Fatalf("EventCount=%d, want 3 (events after the window start)", b.EventCount)
	}
	if !b.Contiguous {
		t.Error("time-window export should be marked Contiguous")
	}
	// Genuinely mid-chain: the anchor is a real predecessor Hash, not genesis.
	if b.BoundaryPrevHash == audit.GenesisHash {
		t.Fatal("mid-chain segment must carry a non-genesis boundary anchor")
	}
	if b.Events[0].PrevHash != b.BoundaryPrevHash {
		t.Errorf("BoundaryPrevHash=%q must equal first event PrevHash=%q", b.BoundaryPrevHash, b.Events[0].PrevHash)
	}
	// The anchor must be the Hash of the last EXCLUDED event (event #3),
	// binding the exported segment to the exact chain position it was cut
	// from.
	full, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{})
	if err != nil {
		t.Fatalf("full export: %v", err)
	}
	if lastExcluded := full.Events[2]; b.BoundaryPrevHash != lastExcluded.Hash {
		t.Errorf("BoundaryPrevHash=%q, want last excluded event's Hash %q", b.BoundaryPrevHash, lastExcluded.Hash)
	}
	// Verifies via the boundary anchor ...
	if err := auditexport.VerifyExportBundle(b); err != nil {
		t.Errorf("VerifyExportBundle on mid-chain segment: %v", err)
	}
	// ... but the genesis-anchored plain verifier must REJECT it, proving
	// VerifyChainSegment is doing real work rather than degenerating to
	// VerifyChain.
	if err := audit.VerifyChain(b.Events); err == nil {
		t.Error("VerifyChain must reject a non-genesis segment")
	}
}

func TestBuildExportBundle_TamperedEventFailsVerify(t *testing.T) {
	t.Parallel()
	sink := recordChain(t, 5)
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{})
	if err != nil {
		t.Fatalf("BuildExportBundle: %v", err)
	}
	b.Events[2].Reason = "tampered"
	if err := auditexport.VerifyExportBundle(b); err == nil {
		t.Fatal("VerifyExportBundle accepted a tampered event")
	} else if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("error should mention hash mismatch: %v", err)
	}
}

// TestBuildExportBundle_RoundTripByteFlipFails proves the on-disk
// artifact is independently loadable AND that flipping a single byte of
// a serialized bundle is detected on reload.
func TestBuildExportBundle_RoundTripByteFlipFails(t *testing.T) {
	t.Parallel()
	sink := recordChain(t, 4)
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{})
	if err != nil {
		t.Fatalf("BuildExportBundle: %v", err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Clean round trip verifies.
	var clean auditexport.ExportBundle
	if err := json.Unmarshal(raw, &clean); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := auditexport.VerifyExportBundle(&clean); err != nil {
		t.Fatalf("clean round trip should verify: %v", err)
	}
	// Flip one hex character inside a reason value and reload.
	corrupt := []byte(strings.Replace(string(raw), `"success"`, `"failure"`, 1))
	var tampered auditexport.ExportBundle
	if err := json.Unmarshal(corrupt, &tampered); err != nil {
		t.Fatalf("unmarshal corrupt: %v", err)
	}
	if err := auditexport.VerifyExportBundle(&tampered); err == nil {
		t.Fatal("VerifyExportBundle accepted a byte-flipped bundle")
	}
}

func TestBuildExportBundle_AgainstSQLiteSink(t *testing.T) {
	t.Parallel()
	sink, err := auditsqlite.New(":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer func() { _ = sink.Close() }()
	i := 0
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		i++
		return eventTime(i)
	}))
	for k := 0; k < 4; k++ {
		r.Record(context.Background(), &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "user"})
	}
	// *sqlite.Sink satisfies auditexport.QueryPager structurally.
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{})
	if err != nil {
		t.Fatalf("BuildExportBundle over sqlite: %v", err)
	}
	if b.EventCount != 4 {
		t.Fatalf("EventCount=%d, want 4", b.EventCount)
	}
	if err := auditexport.VerifyExportBundle(b); err != nil {
		t.Errorf("VerifyExportBundle over sqlite: %v", err)
	}
}

// TestBuildExportBundle_PaginatesBeyondMaxQueryLimit proves the internal
// paging loop, not a single capped Query, drives the export: more events
// than audit.MaxQueryLimit (1000) still all land in the bundle.
func TestBuildExportBundle_PaginatesBeyondMaxQueryLimit(t *testing.T) {
	t.Parallel()
	n := audit.MaxQueryLimit + 200
	sink := recordChain(t, n)
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{})
	if err != nil {
		t.Fatalf("BuildExportBundle: %v", err)
	}
	if b.EventCount != n {
		t.Fatalf("EventCount=%d, want %d (pagination should collect every page)", b.EventCount, n)
	}
	if err := auditexport.VerifyExportBundle(b); err != nil {
		t.Errorf("VerifyExportBundle across pages: %v", err)
	}
}

func TestBuildExportBundle_EmptyRangeIsNoopNotError(t *testing.T) {
	t.Parallel()
	sink := recordChain(t, 3)
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{Since: eventTime(1000)})
	if err != nil {
		t.Fatalf("BuildExportBundle on empty window: %v", err)
	}
	if b.EventCount != 0 || len(b.Events) != 0 {
		t.Fatalf("EventCount=%d len=%d, want 0", b.EventCount, len(b.Events))
	}
	if b.BoundaryPrevHash != audit.GenesisHash || b.HeadHash != "" {
		t.Errorf("empty bundle anchors should be empty: prev=%q head=%q", b.BoundaryPrevHash, b.HeadHash)
	}
	if err := auditexport.VerifyExportBundle(b); err != nil {
		t.Errorf("empty bundle should verify trivially: %v", err)
	}
}

// TestBuildExportBundle_LimitTakesNewest caps the total via q.Limit and
// confirms the contiguous head slice is returned in chain order.
func TestBuildExportBundle_LimitTakesNewest(t *testing.T) {
	t.Parallel()
	sink := recordChain(t, 10)
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{Limit: 3})
	if err != nil {
		t.Fatalf("BuildExportBundle: %v", err)
	}
	if b.EventCount != 3 {
		t.Fatalf("EventCount=%d, want 3 (limit cap)", b.EventCount)
	}
	if !b.Contiguous {
		t.Error("a limit-capped head slice is still contiguous")
	}
	if err := auditexport.VerifyExportBundle(b); err != nil {
		t.Errorf("VerifyExportBundle on limited head slice: %v", err)
	}
}

// TestBuildExportBundle_AttributeFilterIsPerEventVerifiable proves an
// attribute-filtered (non-contiguous) subset is marked !Contiguous,
// verifies per-event, is rejected by the chain-segment check, and still
// detects tampering.
func TestBuildExportBundle_AttributeFilterIsPerEventVerifiable(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(64)
	i := 0
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		i++
		return eventTime(i)
	}))
	// Interleave logins and logouts so a type filter skips events.
	for k := 0; k < 6; k++ {
		r.Record(context.Background(), &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "user"})
		r.Record(context.Background(), &audit.Event{Type: audit.EventLogout, Outcome: audit.OutcomeSuccess, ActorID: "user"})
	}
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{Type: audit.EventLogout})
	if err != nil {
		t.Fatalf("BuildExportBundle: %v", err)
	}
	if b.EventCount != 6 {
		t.Fatalf("EventCount=%d, want 6 logout events", b.EventCount)
	}
	if b.Contiguous {
		t.Fatal("attribute-filtered subset must be marked non-contiguous")
	}
	for _, e := range b.Events {
		if e.Type != audit.EventLogout {
			t.Fatalf("filter leaked a %s event", e.Type)
		}
	}
	if err := auditexport.VerifyExportBundle(b); err != nil {
		t.Errorf("per-event verify of filtered bundle: %v", err)
	}
	// The subset skips intervening logins, so chain-segment linkage fails.
	if err := audit.VerifyChainSegment(b.Events, b.BoundaryPrevHash); err == nil {
		t.Error("chain-segment verify should reject a non-contiguous subset")
	}
	// Tampering is still caught per event.
	b.Events[2].Reason = "tampered"
	if err := auditexport.VerifyExportBundle(b); err == nil {
		t.Error("per-event verify should catch tampering in a filtered bundle")
	}
}

func TestVerifyExportBundle_Guards(t *testing.T) {
	t.Parallel()
	if err := auditexport.VerifyExportBundle(nil); err == nil {
		t.Error("nil bundle should error")
	}
	b := &auditexport.ExportBundle{FormatVersion: auditexport.FormatVersion + 99}
	if err := auditexport.VerifyExportBundle(b); err == nil {
		t.Error("unsupported format version should error")
	}
}

func TestBuildExportBundle_NilPager(t *testing.T) {
	t.Parallel()
	if _, err := auditexport.BuildExportBundle(context.Background(), nil, audit.Query{}); err == nil {
		t.Error("nil pager should error")
	}
}
