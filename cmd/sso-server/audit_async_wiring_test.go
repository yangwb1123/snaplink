package main

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// audit_async_wiring_test.go proves ROADMAP 6e: audit.async.batch_size now
// reaches platform/audit's batch-draining constructor through config; unset
// keeps the historical per-event AsyncSink byte-identical; and a
// batch-incapable composition (webhook fan-out) fails boot loud instead of
// leaving the knob silently inert.

func auditAsyncConfig(batchSize int) *config.Config {
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.Async.Enabled = true
	cfg.Audit.Async.BatchSize = batchSize
	return cfg
}

func closeAsyncSink(t *testing.T, b *appBuilder) {
	t.Helper()
	if b.asyncSink != nil {
		if err := b.asyncSink.Close(context.Background()); err != nil {
			t.Errorf("async sink close: %v", err)
		}
	}
}

func TestAuditAsync_UnsetBatchSizeKeepsPerEventSink(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: auditAsyncConfig(0), logger: quietLogger()}
	if err := b.wireAudit(); err != nil {
		t.Fatalf("wireAudit: %v", err)
	}
	defer closeAsyncSink(t, b)
	if b.asyncSink == nil {
		t.Fatal("async enabled but asyncSink not wired")
	}
	if got := b.asyncSink.BatchSize(); got != 0 {
		t.Errorf("BatchSize() = %d; want 0 (per-event NewAsyncSink, the pre-knob behavior)", got)
	}
}

func TestAuditAsync_BatchSizeSelectsBatchDrainingSink(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: auditAsyncConfig(16), logger: quietLogger()}
	if err := b.wireAudit(); err != nil {
		t.Fatalf("wireAudit: %v", err)
	}
	if b.asyncSink == nil {
		t.Fatal("async enabled but asyncSink not wired")
	}
	if got := b.asyncSink.BatchSize(); got != 16 {
		t.Errorf("BatchSize() = %d; want 16 (NewBatchAsyncSink with the configured size)", got)
	}
	// End-to-end through the wired stack: enqueue on the async sink, drain
	// via Close, then read back through the synchronous Query delegation to
	// the memory primary — batching must not drop or duplicate.
	for i := 0; i < 20; i++ {
		if err := b.asyncSink.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	closeAsyncSink(t, b)
	events, err := b.asyncSink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 20 {
		t.Errorf("got %d events; want 20", len(events))
	}
}

func TestAuditAsync_BatchSizeRejectsWebhookFanOut(t *testing.T) {
	t.Parallel()
	cfg := auditAsyncConfig(16)
	cfg.Audit.Webhook.Enabled = true
	// Never dialed: boot must fail at wiring, before any delivery.
	cfg.Audit.Webhook.URL = "http://127.0.0.1:1/audit"
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireAudit(); err == nil {
		closeAsyncSink(t, b)
		t.Error("wireAudit accepted batch_size with a MultiSink webhook fan-out; want loud boot failure")
	}
}

func TestAuditAsync_NegativeBatchSizeFailsBoot(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: auditAsyncConfig(-3), logger: quietLogger()}
	if err := b.wireAudit(); err == nil {
		closeAsyncSink(t, b)
		t.Error("wireAudit accepted a negative batch_size; want loud boot failure")
	}
}

// TestAuditAsync_BuildAppBootsWithBatch proves the full buildApp path with
// batch draining enabled — including the AsyncSinkCollector registration
// against the batch-mode sink (promauto panics on duplicates, so a clean
// boot is the assertion) — and drains cleanly at shutdown.
func TestAuditAsync_BuildAppBootsWithBatch(t *testing.T) {
	t.Parallel()
	cfg := auditAsyncConfig(8)
	cfg.Metrics.Enabled = true
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp with audit.async.batch_size: %v", err)
	}
	shutdownApp(t, a)
}
