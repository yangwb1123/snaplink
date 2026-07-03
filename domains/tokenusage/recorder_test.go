package tokenusage

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingStore is a Store whose Record blocks until unblock is closed, so
// tests can pin the drainer mid-write and observe queue behavior
// deterministically instead of racing a real timing-dependent backend.
type blockingStore struct {
	unblock  chan struct{}
	recorded int32
}

func (b *blockingStore) Record(ctx context.Context, ev Event) error {
	<-b.unblock
	atomic.AddInt32(&b.recorded, 1)
	return nil
}

func (b *blockingStore) Query(context.Context, Query) ([]Bucket, error) { return nil, nil }

// countingStore is a non-blocking Store that just counts writes, for tests
// that only care about the Recorder <-> Store hand-off, not timing.
type countingStore struct {
	mu    sync.Mutex
	count int
	last  Event
}

func (c *countingStore) Record(_ context.Context, ev Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	c.last = ev
	return nil
}

func (c *countingStore) Query(context.Context, Query) ([]Bucket, error) { return nil, nil }

func (c *countingStore) snapshot() (int, Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count, c.last
}

// TestRecorder_NilIsSafeNoOp mirrors the anomaly.Runner nil-safety contract:
// every method on a nil *Recorder must be a callable no-op so options can
// wire it unconditionally without a nil check at every call site.
func TestRecorder_NilIsSafeNoOp(t *testing.T) {
	var r *Recorder
	r.Start()
	r.Offer(Event{})
	r.SetHooks(Hooks{})
	if got := r.UsageStore(); got != nil {
		t.Errorf("UsageStore() on nil Recorder = %v, want nil", got)
	}
	if err := r.Close(context.Background()); err != nil {
		t.Errorf("Close() on nil Recorder = %v, want nil", err)
	}
}

// TestNewRecorder_NilStoreReturnsNil mirrors NewRecorder's documented
// contract: a nil store yields a nil *Recorder (not a Recorder wrapping a
// nil store, which would panic on the first drain).
func TestNewRecorder_NilStoreReturnsNil(t *testing.T) {
	if r := NewRecorder(nil); r != nil {
		t.Fatalf("NewRecorder(nil) = %v, want nil", r)
	}
}

// TestRecorder_OfferDrainsToStore proves the basic hand-off: an Offered
// event reaches the Store via the background drainer.
func TestRecorder_OfferDrainsToStore(t *testing.T) {
	store := &countingStore{}
	r := NewRecorder(store)
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Offer(Event{ClientID: "c1", Kind: KindAccess, Endpoint: EndpointToken})

	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	count, last := store.snapshot()
	if count != 1 {
		t.Fatalf("store.count = %d, want 1", count)
	}
	if last.ClientID != "c1" || last.Kind != KindAccess {
		t.Errorf("last event = %+v, want ClientID=c1 Kind=access", last)
	}
}

// TestRecorder_OfferStampsZeroTime proves an Event with a zero At gets
// stamped with the observation time, so buckets still land somewhere
// sensible even when a caller forgets to set it.
func TestRecorder_OfferStampsZeroTime(t *testing.T) {
	store := &countingStore{}
	r := NewRecorder(store)
	r.Start()
	before := time.Now()
	r.Offer(Event{ClientID: "c1"})
	_ = r.Close(context.Background())
	after := time.Now()

	_, last := store.snapshot()
	if last.At.Before(before.Add(-time.Second)) || last.At.After(after.Add(time.Second)) {
		t.Errorf("stamped At = %v, want within [%v, %v]", last.At, before, after)
	}
}

// TestRecorder_OfferNeverBlocksOnFullQueue is THE core hot-path contract:
// with a wedged drainer (blockingStore never returns) and a saturated
// queue, Offer must return immediately rather than block the caller —
// telemetry loss is always preferable to added /token latency. Run under
// -race to also prove the drop path has no data race with the drainer.
func TestRecorder_OfferNeverBlocksOnFullQueue(t *testing.T) {
	store := &blockingStore{unblock: make(chan struct{})}
	r := NewRecorder(store, WithQueueSize(2))
	r.Start()

	var dropped int32
	r.SetHooks(Hooks{Dropped: func() { atomic.AddInt32(&dropped, 1) }})

	// Total absorbable without dropping is bounded (one event picked up by
	// the drainer + blocked in Record, plus the queue's own buffer of 2) —
	// sending far more than that guarantees drops regardless of exactly
	// when the drainer goroutine gets scheduled.
	deadline := time.After(2 * time.Second)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			r.Offer(Event{ClientID: "c"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("Offer blocked with a wedged drainer — hot path is not non-blocking")
	}

	close(store.unblock) // let the drainer proceed so Close doesn't hang
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if atomic.LoadInt32(&dropped) == 0 {
		t.Error("Dropped hook never fired — expected at least one shed event on a saturated queue")
	}
}

// TestRecorder_SetHooksFiresRecordedAndTracked proves the metric-emitter
// wiring: Recorded fires with the event's (kind, endpoint) after a
// successful write, and Tracked fires with the store's reported bucket
// count when the store implements TrackedBucketReporter.
func TestRecorder_SetHooksFiresRecordedAndTracked(t *testing.T) {
	store := &trackingStore{}
	r := NewRecorder(store)
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	var recordedKind, recordedEndpoint string
	var tracked int
	var mu sync.Mutex
	r.SetHooks(Hooks{
		Recorded: func(kind, endpoint string) {
			mu.Lock()
			defer mu.Unlock()
			recordedKind, recordedEndpoint = kind, endpoint
		},
		Tracked: func(n int) {
			mu.Lock()
			defer mu.Unlock()
			tracked = n
		},
	})

	r.Offer(Event{Kind: KindRefresh, Endpoint: EndpointIntrospect})
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if recordedKind != string(KindRefresh) || recordedEndpoint != string(EndpointIntrospect) {
		t.Errorf("Recorded hook = (%s, %s), want (refresh, introspect)", recordedKind, recordedEndpoint)
	}
	if tracked != 1 {
		t.Errorf("Tracked hook = %d, want 1", tracked)
	}
}

// trackingStore implements TrackedBucketReporter so
// TestRecorder_SetHooksFiresRecordedAndTracked can exercise the Tracked hook.
type trackingStore struct {
	mu      sync.Mutex
	buckets int
}

func (t *trackingStore) Record(context.Context, Event) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buckets++
	return nil
}

func (t *trackingStore) Query(context.Context, Query) ([]Bucket, error) { return nil, nil }

func (t *trackingStore) TrackedBuckets() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buckets
}

var (
	_ Store                 = (*countingStore)(nil)
	_ Store                 = (*blockingStore)(nil)
	_ Store                 = (*trackingStore)(nil)
	_ TrackedBucketReporter = (*trackingStore)(nil)
)

// TestRecorder_CloseIsIdempotentAndSafeConcurrentWithOffer races Offer
// against Close under -race to prove the RWMutex coupling (Offer holds the
// read lock across the closed-check AND the channel send) prevents the
// send-on-closed-channel panic the doc comment calls out.
func TestRecorder_CloseIsIdempotentAndSafeConcurrentWithOffer(t *testing.T) {
	store := &countingStore{}
	r := NewRecorder(store)
	r.Start()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			r.Offer(Event{ClientID: "race"})
		}
	}()

	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A second Close must be a safe no-op (closeOnce).
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	wg.Wait()
}
