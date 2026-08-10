package auditoutbox

import (
	"context"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// MemorySink is the fail-open audit sink wrapper for the in-process
// (memory) governance path: every accepted event is recorded to the
// base sink AND, when it passes the FactFromAudit gate, enqueued as an
// outbox fact. FAIL-OPEN by construction: the audit record is the
// authoritative write and the wrapper returns only the base sink's
// error; an enqueue failure (outbox full, idempotency conflict) is
// logged via the optional logger and otherwise invisible to the caller
// — governance degrades, audit never does.
//
// The sqlite path does not need this wrapper: platform/audit/sqlite
// WithTxAppender writes the fact in the audit row's own transaction.
type MemorySink struct {
	base   audit.Sink
	store  *MemoryOutboxStore
	logger spi.Logger
}

// NewMemorySink wraps base with a memory outbox. store may be nil (the
// wrapper then only records; enqueues are no-ops) — the audit path must
// never depend on the connector. logger is optional; failures are
// logged at Error level when present.
func NewMemorySink(base audit.Sink, store *MemoryOutboxStore, logger spi.Logger) *MemorySink {
	return &MemorySink{base: base, store: store, logger: logger}
}

// Record implements audit.Sink: record first (authoritative), then
// best-effort enqueue. The class gate is deliberately NOT an error
// surface: a non-login-failure event simply produces no fact, which is
// the documented single-permitted-class behavior.
func (s *MemorySink) Record(ctx context.Context, e *audit.Event) error {
	if s == nil || s.base == nil {
		return nil
	}
	if err := s.base.Record(ctx, e); err != nil {
		return err
	}
	s.enqueue(ctx, e)
	return nil
}

// Query implements audit.Sink (delegated).
func (s *MemorySink) Query(ctx context.Context, q audit.Query) ([]*audit.Event, error) {
	if s == nil || s.base == nil {
		return nil, nil
	}
	return s.base.Query(ctx, q)
}

// Get implements audit.Sink (delegated).
func (s *MemorySink) Get(ctx context.Context, id string) (*audit.Event, error) {
	if s == nil || s.base == nil {
		return nil, nil
	}
	return s.base.Get(ctx, id)
}

func (s *MemorySink) enqueue(ctx context.Context, e *audit.Event) {
	if s.store == nil {
		return
	}
	if err := s.store.AppendFromAudit(ctx, e); err != nil && s.logger != nil {
		s.logger.Error("auditoutbox: fact enqueue failed (audit record preserved)", "event", e.ID, "error", err)
	}
}
