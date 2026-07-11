package serverbuildauthn

import (
	"fmt"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/spi"
)

// BuildAuditAsyncSink wraps the composed sink in the buffered async delivery
// path (audit.async). BatchSize > 1 selects the batch-draining worker
// (audit.NewBatchAsyncSink) so up to BatchSize queued events collapse into one
// RecordBatch transaction; 0 and 1 keep the historical per-event
// audit.NewAsyncSink byte-identically.
//
// Batch mode requires the COMPOSED sink to implement audit.BatchSink. The
// memory/sqlite/postgres primaries all do, but any webhook/cef/ocsf/syslog/
// kafka fan-out wraps them in a MultiSink that does not — that combination
// fails loud here rather than booting with the knob silently inert.
//
// The caller owns the lifecycle (Start/Close) so shutdown ordering stays in
// one place.
func BuildAuditAsyncSink(cfg config.AuditAsyncConfig, sink audit.Sink, logger spi.Logger) (*audit.AsyncSink, error) {
	if cfg.BatchSize < 0 {
		return nil, fmt.Errorf("audit.async.batch_size must be >= 0, got %d", cfg.BatchSize)
	}
	opts := buildAuditAsyncOptions(cfg, logger)
	if cfg.BatchSize <= 1 {
		return audit.NewAsyncSink(sink, opts...), nil
	}
	bs, ok := sink.(audit.BatchSink)
	if !ok {
		return nil, fmt.Errorf("audit.async.batch_size=%d requires a batch-capable sink composition: "+
			"the memory/sqlite/postgres primary alone supports it, but the webhook/cef/ocsf/syslog/kafka "+
			"fan-out does not — disable those sinks or unset batch_size", cfg.BatchSize)
	}
	logger.Info("audit: async batch draining enabled", "batch_size", cfg.BatchSize)
	// queueLen 0: the buffer is carried via WithAsyncBuffer in opts (or the
	// library default), keeping buffer_size semantics identical across modes.
	return audit.NewBatchAsyncSink(bs, cfg.BatchSize, 0, opts...), nil
}

// buildAuditAsyncOptions translates the shared tuning knobs; each falls back
// to the library default when <= 0, matching the pre-batching wiring exactly.
func buildAuditAsyncOptions(cfg config.AuditAsyncConfig, logger spi.Logger) []audit.AsyncOption {
	opts := []audit.AsyncOption{
		audit.WithAsyncDropHandler(func(_ *audit.Event, err error) {
			logger.Error("audit async drop", "error", err)
		}),
	}
	if n := cfg.BufferSize; n > 0 {
		opts = append(opts, audit.WithAsyncBuffer(n))
	}
	if n := cfg.Workers; n > 0 {
		opts = append(opts, audit.WithAsyncWorkers(n))
	}
	if ms := cfg.RecordTimeoutMs; ms > 0 {
		opts = append(opts, audit.WithAsyncRecordTimeout(time.Duration(ms)*time.Millisecond))
	}
	return opts
}
