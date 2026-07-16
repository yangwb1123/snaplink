package audit

import (
	"context"
	"sync"
	"testing"
)

func TestBatchAsyncSink_RecordBatch(t *testing.T) {
	t.Parallel()
	inner := NewMemorySink(0)
	a := NewBatchAsyncSink(inner, 4, 64)
	a.Start()

	for i := 0; i < 10; i++ {
		if err := a.Record(context.Background(), &Event{Type: "test"}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	_ = a.Close(context.Background())

	evts, err := inner.Query(context.Background(), Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evts) != 10 {
		t.Errorf("got %d events, want 10", len(evts))
	}
}

func TestBatchAsyncSink_FallsBackToSingle(t *testing.T) {
	t.Parallel()
	// When the inner sink does NOT implement BatchSink, deliverBatch should
	// fall back to per-event deliver calls. Use a sinkFunc wrapper that
	// implements Sink but not BatchSink.
	var calls int
	w := sinkFunc(func(_ context.Context, _ *Event) error {
		calls++
		return nil
	})
	a := &AsyncSink{
		inner:     w,
		queue:     make(chan *Event, 64),
		workers:   1,
		batchSize: 4,
	}
	a.Start()
	for i := 0; i < 3; i++ {
		_ = a.Record(context.Background(), &Event{Type: "t"})
	}
	_ = a.Close(context.Background())
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

// sinkFunc is a minimal Sink adapter for tests.
type sinkFunc func(context.Context, *Event) error

func (f sinkFunc) Record(ctx context.Context, e *Event) error { return f(ctx, e) }
func (f sinkFunc) Get(_ context.Context, _ string) (*Event, error) {
	return nil, nil
}
func (f sinkFunc) Query(_ context.Context, _ Query) ([]*Event, error) {
	return nil, nil
}

// panickingBatchSink always panics from RecordBatch, simulating a
// misbehaving third-party BatchSink implementation.
type panickingBatchSink struct{}

func (panickingBatchSink) Record(context.Context, *Event) error { panic("boom: single record") }
func (panickingBatchSink) RecordBatch(context.Context, []*Event) error {
	panic("boom: batch record")
}
func (panickingBatchSink) Get(context.Context, string) (*Event, error) {
	return nil, ErrEventNotFound
}
func (panickingBatchSink) Query(context.Context, Query) ([]*Event, error) { return nil, nil }

// TestBatchAsyncSink_PanicInRecordBatchRecovered proves a panic inside the
// inner BatchSink's RecordBatch does not crash the worker goroutine: it is
// reported through the same drop-handler channel a normal batch delivery
// error uses, for every event in the panicking batch.
func TestBatchAsyncSink_PanicInRecordBatchRecovered(t *testing.T) {
	t.Parallel()
	var drops int
	var mu sync.Mutex
	a := NewBatchAsyncSink(panickingBatchSink{}, 4, 64,
		WithAsyncDropHandler(func(_ *Event, _ error) {
			mu.Lock()
			drops++
			mu.Unlock()
		}),
	)
	a.Start()

	for i := 0; i < 5; i++ {
		_ = a.Record(context.Background(), &Event{Type: "test"})
	}
	_ = a.Close(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if drops != 5 {
		t.Fatalf("drops = %d, want 5 (worker must survive the panic and report every event)", drops)
	}
	if got := a.DropsInnerError(); got != 5 {
		t.Fatalf("DropsInnerError = %d, want 5", got)
	}
}

func TestDefaultBatchSize(t *testing.T) {
	t.Parallel()
	if DefaultBatchSize <= 0 {
		t.Errorf("DefaultBatchSize = %d, want > 0", DefaultBatchSize)
	}
}
