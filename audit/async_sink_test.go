package audit_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/audit"
)

// blockingSink lets tests gate Record completion via a release channel
// so queue-fill / shutdown scenarios are deterministic.
type blockingSink struct {
	release chan struct{}
	calls   atomic.Int64
	recErr  error
}

func newBlockingSink() *blockingSink {
	return &blockingSink{release: make(chan struct{})}
}

func (b *blockingSink) Record(ctx context.Context, _ *audit.Event) error {
	b.calls.Add(1)
	select {
	case <-b.release:
		return b.recErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (b *blockingSink) Get(_ context.Context, _ string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}
func (b *blockingSink) Query(_ context.Context, _ audit.Query) ([]*audit.Event, error) {
	return nil, nil
}

// countingSink records the count of delivered events without blocking.
type countingSink struct {
	mu       sync.Mutex
	recorded []*audit.Event
	recErr   error
}

func (c *countingSink) Record(_ context.Context, e *audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recErr != nil {
		return c.recErr
	}
	c.recorded = append(c.recorded, e)
	return nil
}
func (c *countingSink) Get(_ context.Context, _ string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}
func (c *countingSink) Query(_ context.Context, _ audit.Query) ([]*audit.Event, error) {
	return nil, nil
}
func (c *countingSink) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.recorded)
}

func TestAsyncSink_DeliversEventsAsync(t *testing.T) {
	inner := &countingSink{}
	a := audit.NewAsyncSink(inner, audit.WithAsyncBuffer(16))
	a.Start()
	t.Cleanup(func() { _ = a.Close(context.Background()) })

	for i := 0; i < 8; i++ {
		_ = a.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	}

	// Drain by closing — Close blocks until queue empties.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := inner.len(); n != 8 {
		t.Fatalf("delivered=%d want 8", n)
	}
}

func TestAsyncSink_NeverBlocksHotPath(t *testing.T) {
	// 4-slot queue + a sink that hangs forever. After 4 Record calls
	// the queue is full; the next 6 must drop, not block.
	inner := newBlockingSink()
	dropped := atomic.Int64{}
	a := audit.NewAsyncSink(inner,
		audit.WithAsyncBuffer(4),
		audit.WithAsyncWorkers(1),
		audit.WithAsyncDropHandler(func(_ *audit.Event, err error) {
			if errors.Is(err, audit.ErrAsyncQueueFull) {
				dropped.Add(1)
			}
		}),
	)
	a.Start()
	t.Cleanup(func() {
		close(inner.release)
		_ = a.Close(context.Background())
	})

	// Block the single worker on the first event.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			_ = a.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Record blocked despite full queue — hot path must be drop-not-block")
	}

	// 1 in flight + 4 buffered = 5 accepted, 5 dropped (the 10th rounds
	// up — depending on scheduling the inflight slot may or may not have
	// been freed when the burst lands, so accept >= 4).
	if d := dropped.Load(); d < 4 {
		t.Fatalf("dropped=%d want >=4 (queue full)", d)
	}
}

func TestAsyncSink_DropHandlerSurfacesInnerError(t *testing.T) {
	want := errors.New("sink boom")
	inner := &countingSink{recErr: want}
	var seen error
	var mu sync.Mutex
	a := audit.NewAsyncSink(inner,
		audit.WithAsyncDropHandler(func(_ *audit.Event, err error) {
			mu.Lock()
			seen = err
			mu.Unlock()
		}),
	)
	a.Start()

	_ = a.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !errors.Is(seen, want) {
		t.Fatalf("drop handler saw %v want %v", seen, want)
	}
}

func TestAsyncSink_RecordAfterCloseIsDropped(t *testing.T) {
	inner := &countingSink{}
	var dropReason error
	a := audit.NewAsyncSink(inner,
		audit.WithAsyncDropHandler(func(_ *audit.Event, err error) { dropReason = err }),
	)
	a.Start()

	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_ = a.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	if !errors.Is(dropReason, audit.ErrAsyncSinkClosed) {
		t.Fatalf("drop reason = %v want ErrAsyncSinkClosed", dropReason)
	}
	if inner.len() != 0 {
		t.Fatalf("post-close event leaked: %d", inner.len())
	}
}

func TestAsyncSink_CloseDeadlineEnforced(t *testing.T) {
	// A sink that never releases pins the worker — Close must respect
	// the supplied context.
	inner := newBlockingSink()
	a := audit.NewAsyncSink(inner, audit.WithAsyncBuffer(4))
	a.Start()
	t.Cleanup(func() { close(inner.release) })

	_ = a.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	// Worker is blocked on inner.Record. Close with a tight deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := a.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close err = %v want DeadlineExceeded", err)
	}
}

func TestAsyncSink_RecordContextCancellationIgnored(t *testing.T) {
	// Hot-path ctx cancellation MUST NOT abort delivery — the request
	// goroutine often returns before the worker drains the queue.
	inner := &countingSink{}
	a := audit.NewAsyncSink(inner)
	a.Start()
	t.Cleanup(func() { _ = a.Close(context.Background()) })

	ctx, cancel := context.WithCancel(context.Background())
	_ = a.Record(ctx, &audit.Event{Type: audit.EventLogin})
	cancel() // cancel BEFORE worker drains

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if inner.len() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("event not delivered after caller ctx cancellation: %d", inner.len())
}

func TestAsyncSink_ConcurrentWorkers(t *testing.T) {
	// 4 workers + 4-slot queue + slow sink → drain rate roughly 4x.
	inner := &slowSink{delay: 30 * time.Millisecond}
	a := audit.NewAsyncSink(inner,
		audit.WithAsyncBuffer(64),
		audit.WithAsyncWorkers(4),
	)
	a.Start()
	t.Cleanup(func() { _ = a.Close(context.Background()) })

	const total = 12
	for i := 0; i < total; i++ {
		_ = a.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	elapsed := time.Since(start)

	// Serial would be 12 * 30ms = 360ms. 4 workers should land near
	// 3 * 30ms = 90ms. 200ms ceiling tolerates CI jitter while still
	// catching a serial regression (which would exceed 300ms).
	if elapsed > 200*time.Millisecond {
		t.Fatalf("4-worker drain took %v — expected parallelism failed", elapsed)
	}
	if inner.count.Load() != int64(total) {
		t.Fatalf("delivered=%d want %d", inner.count.Load(), total)
	}
}

type slowSink struct {
	delay time.Duration
	count atomic.Int64
}

func (s *slowSink) Record(_ context.Context, _ *audit.Event) error {
	time.Sleep(s.delay)
	s.count.Add(1)
	return nil
}
func (s *slowSink) Get(_ context.Context, _ string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}
func (s *slowSink) Query(_ context.Context, _ audit.Query) ([]*audit.Event, error) {
	return nil, nil
}

func TestAsyncSink_ReadPathDelegated(t *testing.T) {
	inner := audit.NewMemorySink(8)
	a := audit.NewAsyncSink(inner)
	a.Start()
	t.Cleanup(func() { _ = a.Close(context.Background()) })

	_ = a.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	// Wait for delivery (synchronous drain via Close).
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := a.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Query len=%d want 1", len(got))
	}
}

func TestAsyncSink_StartIsIdempotent(t *testing.T) {
	inner := &countingSink{}
	a := audit.NewAsyncSink(inner, audit.WithAsyncWorkers(2))
	a.Start()
	a.Start() // must not double-spawn workers (would deadlock on Close via wg)

	_ = a.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if inner.len() != 1 {
		t.Fatalf("delivered=%d want 1", inner.len())
	}
}

func TestAsyncSink_PendingAndCapacityGauges(t *testing.T) {
	inner := newBlockingSink()
	a := audit.NewAsyncSink(inner, audit.WithAsyncBuffer(8))
	a.Start()
	t.Cleanup(func() {
		close(inner.release)
		_ = a.Close(context.Background())
	})

	if c := a.Capacity(); c != 8 {
		t.Fatalf("Capacity=%d want 8", c)
	}
	// 1 grabbed by worker (blocked), 5 sit in queue.
	for i := 0; i < 6; i++ {
		_ = a.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if a.Pending() == 5 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("Pending=%d want 5", a.Pending())
}
