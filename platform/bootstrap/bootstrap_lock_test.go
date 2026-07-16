package bootstrap_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/bootstrap"
	"github.com/snaplink/sso/platform/bootstrap/lock"
	"github.com/snaplink/sso/platform/bootstrap/lockfile"
	"github.com/snaplink/sso/platform/bootstrap/locknoop"
	"github.com/snaplink/sso/platform/bootstrap/memory"
)

// fakeLock is a minimal in-memory Lock that lets each test script the
// outcomes of TryAcquire / Renew. Sufficient for exercising every
// branch in runLocked / acquireLock / heartbeat without standing up
// etcd or relying on flock timing.
type fakeLock struct {
	mu          sync.Mutex
	heldBy      *fakeHandle   // currently held by this handle (nil = free)
	queue       chan struct{} // signal when lock frees; nil disables blocking notifications
	acquireErrs []error       // pop one per TryAcquire (nil = real attempt)
	tokens      atomic.Uint64
}

func newFakeLock() *fakeLock { return &fakeLock{queue: make(chan struct{}, 16)} }

func (f *fakeLock) TryAcquire(_ context.Context, key string, _ time.Duration) (lock.Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.acquireErrs) > 0 {
		err := f.acquireErrs[0]
		f.acquireErrs = f.acquireErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	if f.heldBy != nil {
		return nil, lock.ErrLocked
	}
	h := &fakeHandle{parent: f, key: key, token: f.tokens.Add(1)}
	f.heldBy = h
	return h, nil
}

func (f *fakeLock) freeLocked() {
	f.heldBy = nil
	select {
	case f.queue <- struct{}{}:
	default:
	}
}

type fakeHandle struct {
	parent      *fakeLock
	key         string
	token       uint64
	renewFails  atomic.Int32 // how many Renew calls remain before returning lock.ErrLockLost
	renewPanics atomic.Bool  // Renew panics once instead of returning an error
	released    atomic.Bool
}

func (h *fakeHandle) Renew(context.Context) error {
	if h.released.Load() {
		return lock.ErrLockLost
	}
	if h.renewPanics.CompareAndSwap(true, false) {
		// Simulates a bug in a third-party Lock.Handle implementation
		// (redis, postgres advisory, a hand-rolled backend) — the Runner
		// must not let this crash the whole process.
		panic("simulated Renew panic from a buggy Lock.Handle implementation")
	}
	if h.renewFails.Load() > 0 {
		if h.renewFails.Add(-1) == 0 {
			// Simulate the lease being lost from etcd's perspective: the
			// handle is no longer valid even though Release wasn't called.
			h.parent.mu.Lock()
			if h.parent.heldBy == h {
				h.parent.freeLocked()
			}
			h.parent.mu.Unlock()
			return lock.ErrLockLost
		}
	}
	return nil
}

func (h *fakeHandle) Release(context.Context) error {
	if !h.released.CompareAndSwap(false, true) {
		return nil
	}
	h.parent.mu.Lock()
	defer h.parent.mu.Unlock()
	if h.parent.heldBy == h {
		h.parent.freeLocked()
	}
	return nil
}

func (h *fakeHandle) FencingToken() uint64 { return h.token }

// --- tests ---

func TestRunner_NoLock_BackwardCompatible(t *testing.T) {
	t.Parallel()
	// Existing single-replica path stays untouched when WithLock is omitted.
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr)
	hits := &recorder{}
	r.Register(step("only", 1, hits.ran))
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hits.calls.Load() != 1 {
		t.Errorf("expected 1 invocation, got %d", hits.calls.Load())
	}
}

func TestRunner_NoopLock_RunsNormally(t *testing.T) {
	t.Parallel()
	// noop lock should behave exactly like no lock from the Runner's view.
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr,
		bootstrap.WithLock(noop.New(), "/test/ns"),
	)
	hits := &recorder{}
	r.Register(step("a", 1, hits.ran))
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hits.calls.Load() != 1 {
		t.Errorf("expected 1, got %d", hits.calls.Load())
	}
}

func TestRunner_Contended_NonBlocking_ReturnsErrLocked(t *testing.T) {
	t.Parallel()
	fl := newFakeLock()
	// Pre-acquire so the Runner's TryAcquire fails.
	pre, err := fl.TryAcquire(context.Background(), "/k", time.Second)
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	t.Cleanup(func() { _ = pre.Release(context.Background()) })

	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr, bootstrap.WithLock(fl, "/k"))
	r.Register(step("a", 1, func(_ context.Context) error { return nil }))

	err = r.Run(context.Background())
	if !errors.Is(err, bootstrap.ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
}

func TestRunner_Contended_Blocking_RetriesUntilFree(t *testing.T) {
	t.Parallel()
	fl := newFakeLock()
	pre, err := fl.TryAcquire(context.Background(), "/k", time.Second)
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}

	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr,
		bootstrap.WithLock(fl, "/k"),
		bootstrap.WithLockBlocking(true, 50*time.Millisecond),
	)
	hits := &recorder{}
	r.Register(step("a", 1, hits.ran))

	// Release after a short delay; the Runner should observe the free
	// slot on its next backoff tick and proceed.
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = pre.Release(context.Background())
	}()

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hits.calls.Load() != 1 {
		t.Errorf("expected 1, got %d", hits.calls.Load())
	}
}

func TestRunner_LockLost_DuringStep_AbortsAndSurfacesErrLockLost(t *testing.T) {
	t.Parallel()
	fl := newFakeLock()
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr,
		bootstrap.WithLock(fl, "/k"),
		bootstrap.WithLockTTL(120*time.Millisecond), // heartbeat = ~40ms
	)
	// Schedule the FIRST handle's first Renew to fail.
	// We can't reach the handle until TryAcquire is called from within
	// Run, so we hook through the lock's heldBy after a sleep.
	go func() {
		// Let the Runner enter the step + start the heartbeat.
		time.Sleep(50 * time.Millisecond)
		fl.mu.Lock()
		if fl.heldBy != nil {
			fl.heldBy.renewFails.Store(1)
		}
		fl.mu.Unlock()
	}()
	// A long step that the heartbeat failure must interrupt.
	r.Register(step("slow", 1, func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			return nil
		}
	}))

	err := r.Run(context.Background())
	if !errors.Is(err, bootstrap.ErrLockLost) {
		t.Fatalf("err = %v, want ErrLockLost", err)
	}
	v, _ := tr.AppliedVersion(context.Background(), "ns")
	if v != 0 {
		t.Errorf("version = %d, want 0 (step must not be marked applied after lock loss)", v)
	}
}

// TestRunner_HeartbeatPanic_DoesNotCrashProcess proves a panic inside a
// pluggable Lock.Handle.Renew (a bug in a third-party backend, not one of
// the in-tree ones) is contained by the heartbeat goroutine instead of
// taking down the whole process. Before the fix, heartbeat called
// h.Renew(ctx) with no recover; since an unrecovered panic in ANY
// goroutine is process-fatal in Go, this test process itself would abort
// before ever reaching the assertions below. The fix folds the panic into
// ErrLockLost, matching the fail-closed semantics an ordinary Renew
// failure already has.
func TestRunner_HeartbeatPanic_DoesNotCrashProcess(t *testing.T) {
	t.Parallel()
	fl := newFakeLock()
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr,
		bootstrap.WithLock(fl, "/k"),
		bootstrap.WithLockTTL(120*time.Millisecond), // heartbeat = ~40ms
	)
	go func() {
		// Let the Runner enter the step + start the heartbeat before
		// arming the panic on the live handle.
		time.Sleep(50 * time.Millisecond)
		fl.mu.Lock()
		if fl.heldBy != nil {
			fl.heldBy.renewPanics.Store(true)
		}
		fl.mu.Unlock()
	}()
	r.Register(step("slow", 1, func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			return nil
		}
	}))

	err := r.Run(context.Background())
	if !errors.Is(err, bootstrap.ErrLockLost) {
		t.Fatalf("err = %v, want ErrLockLost", err)
	}
	v, _ := tr.AppliedVersion(context.Background(), "ns")
	if v != 0 {
		t.Errorf("version = %d, want 0 (step must not be marked applied after a heartbeat panic)", v)
	}
}

func TestRunner_LockReleased_OnSuccessAndOnError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		step bootstrap.Step
	}{
		{"success", step("ok", 1, func(_ context.Context) error { return nil })},
		{"error", step("bad", 1, func(_ context.Context) error { return errors.New("boom") })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fl := newFakeLock()
			tr := memory.New()
			r := bootstrap.NewRunner("ns", tr, bootstrap.WithLock(fl, "/k"))
			r.Register(tc.step)
			_ = r.Run(context.Background())
			fl.mu.Lock()
			held := fl.heldBy
			fl.mu.Unlock()
			if held != nil {
				t.Errorf("lock should be released after Run, still held by token=%d", held.token)
			}
		})
	}
}

func TestRunner_LockAuditEvents(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr,
		bootstrap.WithLock(noop.New(), "/k"),
		bootstrap.WithRecorder(rec),
	)
	r.Register(step("a", 1, func(_ context.Context) error { return nil }))
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Expect at least: lock_acquired + step_applied + lock_released.
	events, err := sink.Query(context.Background(), audit.Query{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	got := map[audit.EventType]int{}
	for _, e := range events {
		got[e.Type]++
	}
	for _, want := range []audit.EventType{
		audit.EventBootstrapLockAcquired,
		audit.EventBootstrapStepApplied,
		audit.EventBootstrapLockReleased,
	} {
		if got[want] == 0 {
			t.Errorf("missing %q in audit events: %v", want, got)
		}
	}
}

// --- file lock end-to-end ---

func TestRunner_FileLock_EndToEnd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fl := file.New(dir)
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr, bootstrap.WithLock(fl, "boot"))
	r.Register(step("a", 1, func(_ context.Context) error { return nil }))
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	v, _ := tr.AppliedVersion(context.Background(), "ns")
	if v != 1 {
		t.Errorf("version = %d, want 1", v)
	}
	// A second Runner using the SAME directory should be able to take
	// the lock now that the first finished.
	r2 := bootstrap.NewRunner("ns", tr, bootstrap.WithLock(file.New(dir), "boot"))
	r2.Register(step("a", 1, func(_ context.Context) error { return nil }))
	if err := r2.Run(context.Background()); err != nil {
		t.Fatalf("Run 2: %v", err)
	}
}
