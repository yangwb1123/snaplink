package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

// fakeTipSink is a read-capable Sink that also implements ChainTip,
// returning a configurable head hash + error so the resume seam can be
// driven without a real database. Real in-memory storage, no mock
// framework — it just exposes a fixed tip.
type fakeTipSink struct {
	*audit.MemorySink
	tip    string
	tipErr error
}

func newFakeTipSink(tip string) *fakeTipSink {
	return &fakeTipSink{MemorySink: audit.NewMemorySink(64), tip: tip}
}

func (f *fakeTipSink) LastHash(context.Context) (string, error) {
	return f.tip, f.tipErr
}

// MemorySink does NOT implement ChainTip, so WithHashChain over it seeds
// genesis — the first event carries PrevHash == "".
func TestWithHashChain_MemorySinkSeedsGenesis(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(4)
	rec := audit.New(sink, audit.WithHashChain())
	rec.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	got, _ := sink.Query(context.Background(), audit.Query{Limit: 4})
	if got[0].PrevHash != "" {
		t.Fatalf("memory-only sink should seed genesis, PrevHash = %q", got[0].PrevHash)
	}
}

// When the sink implements ChainTip with a non-empty head, the chain
// RESUMES: the first event's PrevHash equals the persisted tip.
func TestWithHashChain_ResumesFromTip(t *testing.T) {
	t.Parallel()
	const persistedHead = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	sink := newFakeTipSink(persistedHead)
	rec := audit.New(sink, audit.WithHashChain())
	rec.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	got, _ := sink.Query(context.Background(), audit.Query{Limit: 4})
	if got[0].PrevHash != persistedHead {
		t.Fatalf("first post-restart PrevHash = %q, want resumed tip %q", got[0].PrevHash, persistedHead)
	}
}

// A tip-read error is best-effort: seed genesis and continue so a degraded
// durable sink never blocks recording.
func TestWithHashChain_TipErrorSeedsGenesis(t *testing.T) {
	t.Parallel()
	sink := newFakeTipSink("ignored-because-error")
	sink.tipErr = context.DeadlineExceeded
	rec := audit.New(sink, audit.WithHashChain())
	rec.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	got, _ := sink.Query(context.Background(), audit.Query{Limit: 4})
	if got[0].PrevHash != "" {
		t.Fatalf("tip error should fall back to genesis, PrevHash = %q", got[0].PrevHash)
	}
}

// MultiSink.LastHash delegates to the first wrapped sink implementing
// ChainTip; a fan-out with no durable leaf returns genesis ("").
func TestMultiSink_LastHashDelegatesToChainTipLeaf(t *testing.T) {
	t.Parallel()
	tip := newFakeTipSink("abc123")
	multi := audit.NewMultiSink(audit.NewMemorySink(4), tip)
	got, err := multi.LastHash(context.Background())
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if got != "abc123" {
		t.Fatalf("LastHash = %q, want abc123 (from durable leaf)", got)
	}
}

func TestMultiSink_LastHashNoDurableLeafIsGenesis(t *testing.T) {
	t.Parallel()
	multi := audit.NewMultiSink(audit.NewMemorySink(4), audit.NewMemorySink(4))
	got, err := multi.LastHash(context.Background())
	if err != nil || got != "" {
		t.Fatalf("LastHash = %q, err=%v, want genesis", got, err)
	}
}

// AsyncSink.LastHash delegates synchronously to the inner ChainTip,
// bypassing the write queue.
func TestAsyncSink_LastHashDelegatesToInner(t *testing.T) {
	t.Parallel()
	tip := newFakeTipSink("xyz789")
	async := audit.NewAsyncSink(tip)
	got, err := async.LastHash(context.Background())
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if got != "xyz789" {
		t.Fatalf("LastHash = %q, want xyz789", got)
	}
}

func TestAsyncSink_LastHashInnerWithoutChainTipIsGenesis(t *testing.T) {
	t.Parallel()
	async := audit.NewAsyncSink(audit.NewMemorySink(4))
	got, err := async.LastHash(context.Background())
	if err != nil || got != "" {
		t.Fatalf("LastHash = %q, err=%v, want genesis", got, err)
	}
}

// End-to-end: the resume seam works through the standard
// Async -> Multi -> ChainTip-leaf pipeline that WithHashChain reads.
func TestWithHashChain_ResumesThroughAsyncMultiPipeline(t *testing.T) {
	t.Parallel()
	const head = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	leaf := newFakeTipSink(head)
	pipeline := audit.NewAsyncSink(audit.NewMultiSink(leaf))
	rec := audit.New(pipeline, audit.WithHashChain())
	pipeline.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = pipeline.Close(ctx)
	}()

	rec.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	// Drain so the async worker delivers into the leaf.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = pipeline.Close(ctx)

	got, _ := leaf.Query(context.Background(), audit.Query{Limit: 4})
	if len(got) != 1 {
		t.Fatalf("expected 1 delivered event, got %d", len(got))
	}
	if got[0].PrevHash != head {
		t.Fatalf("PrevHash = %q, want resumed head %q through pipeline", got[0].PrevHash, head)
	}
}

// AddSink fans every event to the extra tap IN ADDITION to the primary,
// with redaction + chaining applied once before either sink sees it.
func TestRecorder_AddSinkTapsEveryEvent(t *testing.T) {
	t.Parallel()
	primary := audit.NewMemorySink(8)
	tap := audit.NewMemorySink(8)
	rec := audit.New(primary, audit.WithHashChain())
	rec.AddSink(tap)

	rec.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	p, _ := primary.Query(context.Background(), audit.Query{Limit: 8})
	tp, _ := tap.Query(context.Background(), audit.Query{Limit: 8})
	if len(p) != 1 || len(tp) != 1 {
		t.Fatalf("primary=%d tap=%d, want 1 each", len(p), len(tp))
	}
	// Same chained event reached both — identical Hash.
	if p[0].Hash == "" || p[0].Hash != tp[0].Hash {
		t.Fatalf("tap saw a different (or unchained) event: primary=%q tap=%q", p[0].Hash, tp[0].Hash)
	}
}

func TestRecorder_AddSinkNilSafe(t *testing.T) {
	t.Parallel()
	// nil recorder + nil extra are both no-ops.
	var nilRec *audit.Recorder
	nilRec.AddSink(audit.NewMemorySink(1)) // must not panic

	primary := audit.NewMemorySink(4)
	rec := audit.New(primary)
	rec.AddSink(nil) // no-op
	if rec.Sink() != primary {
		t.Fatal("AddSink(nil) should leave the original sink in place")
	}
}

// AsyncSink and RetryingSink serve Get synchronously from the inner sink
// (only the write path is wrapped).
func TestComposingSinks_GetDelegatesToInner(t *testing.T) {
	t.Parallel()
	inner := audit.NewMemorySink(4)
	_ = inner.Record(context.Background(), &audit.Event{ID: "find-me", Type: audit.EventLogin})

	async := audit.NewAsyncSink(inner)
	if e, err := async.Get(context.Background(), "find-me"); err != nil || e.ID != "find-me" {
		t.Fatalf("async Get = %+v, err=%v", e, err)
	}

	retry := audit.NewRetryingSink(inner)
	if e, err := retry.Get(context.Background(), "find-me"); err != nil || e.ID != "find-me" {
		t.Fatalf("retry Get = %+v, err=%v", e, err)
	}
}

// WithAsyncRecordTimeout caps the inner Record; an event still delivers
// when the inner sink is fast.
func TestAsyncSink_WithRecordTimeoutDelivers(t *testing.T) {
	t.Parallel()
	inner := audit.NewMemorySink(4)
	async := audit.NewAsyncSink(inner, audit.WithAsyncRecordTimeout(time.Second))
	async.Start()

	_ = async.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got, _ := inner.Query(context.Background(), audit.Query{Limit: 4})
	if len(got) != 1 {
		t.Fatalf("expected 1 delivered event with timeout set, got %d", len(got))
	}
}
