package auditsink

import (
	"context"

	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// BatchSink is an optional extension of [Sink] for sinks that can persist
// multiple events in a single operation — a single SQLite transaction instead
// of N independent INSERTs, for example. Implementations must be safe for
// concurrent use.
//
// A BatchSink is most useful when paired with [NewBatchAsyncSink]: the async
// worker drains the queue in bursts and calls RecordBatch instead of
// per-event Record, collapsing the per-transaction overhead.
type BatchSink interface {
	auditspi.Sink
	// RecordBatch persists all events in a single atomic operation.
	// It MUST be equivalent to calling Record for each event in order and
	// MUST return a non-nil error only when NO event was persisted (partial
	// writes are not representable — the caller retries the whole batch).
	RecordBatch(ctx context.Context, events []*auditspi.Event) error
}
