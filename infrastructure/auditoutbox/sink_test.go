package auditoutbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// TestMemorySink_FailOpenEnqueue proves the memory wrapper's fail-open
// contract: the base sink's error is the only error the caller sees,
// and an enqueue failure (simulated by a store poisoned with a
// conflicting idempotency key) never fails the record.
func TestMemorySink_FailOpenEnqueue(t *testing.T) {
	base := audit.NewMemorySink(50)
	store := NewMemoryOutboxStore()
	ctx := context.Background()

	// Poison the store: same idempotency key, different fact -> conflict.
	fact, err := FactFromAudit(loginFailure("e1", "t1"))
	if err != nil {
		t.Fatalf("fact: %v", err)
	}
	_ = store.Append(ctx, fact)
	conflict := *fact
	conflict.ID = "e-other"
	conflict.PayloadDigest = "different"
	_ = store.Append(ctx, &conflict)

	wrapped := NewMemorySink(base, store, nil)
	ev := loginFailure("e1", "t1")
	if err := wrapped.Record(ctx, ev); err != nil {
		t.Fatalf("record must not fail on enqueue conflict: %v", err)
	}
	// The audit record is authoritative and present.
	if _, err := base.Get(ctx, "e1"); err != nil {
		t.Errorf("audit record missing: %v", err)
	}
}

// TestMemorySink_BaseErrorPropagates proves the wrapper never swallows a
// real audit-sink failure.
func TestMemorySink_BaseErrorPropagates(t *testing.T) {
	base := &failingSink{err: errors.New("audit store down")}
	wrapped := NewMemorySink(base, NewMemoryOutboxStore(), nil)
	err := wrapped.Record(context.Background(), loginFailure("e1", "t1"))
	if !errors.Is(err, base.err) {
		t.Fatalf("err = %v, want base error", err)
	}
}

// TestMemorySink_ClassGateNoFact proves only login-failure events
// enqueue facts through the memory path (the same fail-closed gate as
// the sqlite path).
func TestMemorySink_ClassGateNoFact(t *testing.T) {
	base := audit.NewMemorySink(50)
	store := NewMemoryOutboxStore()
	wrapped := NewMemorySink(base, store, nil)
	if err := wrapped.Record(context.Background(), &audit.Event{
		ID: "tok-1", Type: audit.EventTokenIssued, Outcome: audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(), TenantID: "t1",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	pending, err := store.Pending(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("non-permitted class enqueued a fact: %v %+v", err, pending)
	}
}

// failingSink is a minimal audit.Sink that always fails Record.
type failingSink struct {
	err error
}

func (f *failingSink) Record(context.Context, *audit.Event) error { return f.err }
func (f *failingSink) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, nil
}
func (f *failingSink) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}
