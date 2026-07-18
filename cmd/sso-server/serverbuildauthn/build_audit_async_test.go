package serverbuildauthn

import (
	"context"
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/audit"
)

// TestBuildAuditAsyncSink_DefaultIsPerEvent — an async block without
// batch_size keeps the historical per-event NewAsyncSink path (BatchSize 0),
// pinning the byte-identical-default contract for existing configs.
func TestBuildAuditAsyncSink_DefaultIsPerEvent(t *testing.T) {
	t.Parallel()
	a, err := BuildAuditAsyncSink(config.AuditAsyncConfig{Enabled: true}, audit.NewMemorySink(0), testLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := a.BatchSize(); got != 0 {
		t.Errorf("BatchSize() = %d; want 0 (per-event)", got)
	}
}

// TestBuildAuditAsyncSink_BatchSizeOneStaysPerEvent — batch_size: 1 must mean
// "one event per delivery" (per-event), NOT trip the library constructor's
// <= 1 fallback to DefaultBatchSize (64). Guards against surprise-enabling
// 64-event batching from a knob that reads as disabling it.
func TestBuildAuditAsyncSink_BatchSizeOneStaysPerEvent(t *testing.T) {
	t.Parallel()
	a, err := BuildAuditAsyncSink(config.AuditAsyncConfig{Enabled: true, BatchSize: 1}, audit.NewMemorySink(0), testLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := a.BatchSize(); got != 0 {
		t.Errorf("BatchSize() = %d; want 0 (per-event, never DefaultBatchSize)", got)
	}
}

// TestBuildAuditAsyncSink_BatchModeRoundTrip — batch_size > 1 against the
// batch-capable memory primary constructs the batch drainer with the exact
// configured size, and every recorded event survives the queue + RecordBatch
// path out to the inner sink.
func TestBuildAuditAsyncSink_BatchModeRoundTrip(t *testing.T) {
	t.Parallel()
	inner := audit.NewMemorySink(0)
	a, err := BuildAuditAsyncSink(config.AuditAsyncConfig{Enabled: true, BatchSize: 8}, inner, testLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := a.BatchSize(); got != 8 {
		t.Errorf("BatchSize() = %d; want 8", got)
	}
	a.Start()
	for i := 0; i < 20; i++ {
		if err := a.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	events, err := inner.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 20 {
		t.Errorf("got %d events; want 20 (batch drain must not drop)", len(events))
	}
}

// TestBuildAuditAsyncSink_TuningKnobsApplyInBatchMode — buffer_size keeps its
// meaning when batch mode is on (carried via the same AsyncOption set, not
// the constructor's queueLen parameter).
func TestBuildAuditAsyncSink_TuningKnobsApplyInBatchMode(t *testing.T) {
	t.Parallel()
	a, err := BuildAuditAsyncSink(config.AuditAsyncConfig{
		Enabled: true, BatchSize: 4, BufferSize: 16, Workers: 2, RecordTimeoutMs: 50,
	}, audit.NewMemorySink(0), testLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := a.Capacity(); got != 16 {
		t.Errorf("Capacity() = %d; want 16 (buffer_size must apply in batch mode)", got)
	}
}

// TestBuildAuditAsyncSink_RejectsNegativeBatchSize — negative values are a
// mangled config, not a "use the default" request; boot fails loud.
func TestBuildAuditAsyncSink_RejectsNegativeBatchSize(t *testing.T) {
	t.Parallel()
	_, err := BuildAuditAsyncSink(config.AuditAsyncConfig{Enabled: true, BatchSize: -1}, audit.NewMemorySink(0), testLogger())
	if err == nil {
		t.Fatal("expected error for negative batch_size")
	}
}

// TestBuildAuditAsyncSink_RejectsNonBatchComposition — batch_size > 1 with a
// MultiSink-wrapped composition (what webhook/SIEM/kafka fan-out produces —
// no RecordBatch) must fail boot loud instead of leaving the knob silently
// inert.
func TestBuildAuditAsyncSink_RejectsNonBatchComposition(t *testing.T) {
	t.Parallel()
	composed := audit.NewMultiSink(audit.NewMemorySink(0))
	_, err := BuildAuditAsyncSink(config.AuditAsyncConfig{Enabled: true, BatchSize: 8}, composed, testLogger())
	if err == nil {
		t.Fatal("expected error: MultiSink composition cannot honor batch_size")
	}
}
