package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/bootstrap/lock"
)

// Re-export the lock sentinels so callers can errors.Is against them
// without a separate import. Aliased values, not new identities — they
// compare equal to the underlying lock.Err* sentinels.
var (
	ErrLocked   = lock.ErrLocked
	ErrLockLost = lock.ErrLockLost
)

// Step is one init action. Implementations should be:
//   - idempotent in spirit (the Runner promises only-once, but bugs happen)
//   - cheap to instantiate (Steps are constructed at boot regardless of
//     whether they actually run)
//   - blocking (Run is called synchronously; spawn goroutines if you want)
type Step interface {
	Name() string
	Version() int
	Run(ctx context.Context) error
}

// StepFunc is the convenience constructor for stateless steps.
func StepFunc(name string, version int, run func(ctx context.Context) error) Step {
	return &funcStep{name: name, version: version, run: run}
}

type funcStep struct {
	name    string
	version int
	run     func(ctx context.Context) error
}

func (f *funcStep) Name() string                  { return f.name }
func (f *funcStep) Version() int                  { return f.version }
func (f *funcStep) Run(ctx context.Context) error { return f.run(ctx) }

// Tracker persists "highest applied version" per namespace. Implementations
// must be safe for concurrent Runners with different namespaces (the same
// namespace running twice in parallel is the caller's problem — wrap with
// a distributed lock if needed).
type Tracker interface {
	AppliedVersion(ctx context.Context, namespace string) (int, error)
	MarkApplied(ctx context.Context, namespace string, version int, name string) error
	Close() error
}

// ErrUnsupported is returned by Trackers that don't implement an operation.
var ErrUnsupported = errors.New("bootstrap: unsupported tracker operation")

// Runner runs pending Steps for one namespace. Construct with NewRunner +
// Register, then call Run once at boot.
type Runner struct {
	namespace string
	tracker   Tracker
	recorder  *audit.Recorder
	logger    Logger

	// Distributed lock — nil disables coordination (single-replica mode).
	// When set, Run wraps step iteration in TryAcquire + heartbeat +
	// Release so peers don't race the Tracker.
	lock         lock.Lock
	lockKey      string
	lockTTL      time.Duration
	lockBlocking bool
	lockBackoff  time.Duration

	mu    sync.Mutex
	steps []Step
}

// Default tunables for the lock layer.
const (
	defaultLockTTL     = 30 * time.Second
	defaultLockBackoff = 2 * time.Second
)

// Logger is the minimal log surface the Runner needs. Compatible with
// *log/slog.Logger via a thin adapter.
type Logger interface {
	Info(msg string, kv ...any)
	Error(msg string, kv ...any)
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// Option tweaks Runner construction.
type Option func(*Runner)

// WithRecorder wires an audit.Recorder. Every Step run/skip/failure emits
// an audit event tagged with the namespace + step name + version.
func WithRecorder(r *audit.Recorder) Option { return func(rn *Runner) { rn.recorder = r } }

// WithLogger sets the diagnostic logger. Defaults to a no-op.
func WithLogger(l Logger) Option { return func(rn *Runner) { rn.logger = l } }

// WithLock enables multi-replica coordination. The Runner takes the
// lock at the start of Run, runs a heartbeat goroutine that Renews on
// ttl/3, and Releases when Run returns. Heartbeat failure cancels the
// in-flight step's context.
//
// key namespaces the lock — different runners with different keys do
// not interfere. Pass a stable per-deployment key like
// "/sso/bootstrap/sso-server".
func WithLock(l lock.Lock, key string) Option {
	return func(rn *Runner) {
		rn.lock = l
		rn.lockKey = key
	}
}

// WithLockTTL overrides the lease TTL. Defaults to 30s. Must be at
// least a few seconds — the heartbeat fires at ttl/3, and short TTLs
// leave no margin for stop-the-world pauses.
func WithLockTTL(ttl time.Duration) Option {
	return func(rn *Runner) { rn.lockTTL = ttl }
}

// WithLockBlocking switches contention behavior. Default false:
// TryAcquire failure returns ErrLocked immediately. true: retry every
// backoff (default 2s) until acquired or ctx cancels.
func WithLockBlocking(blocking bool, backoff time.Duration) Option {
	return func(rn *Runner) {
		rn.lockBlocking = blocking
		rn.lockBackoff = backoff
	}
}

// NewRunner constructs a Runner for namespace. Tracker may be shared across
// runners with different namespaces — they don't interfere.
func NewRunner(namespace string, tracker Tracker, opts ...Option) *Runner {
	r := &Runner{namespace: namespace, tracker: tracker, logger: nopLogger{}}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Register adds Steps. Order doesn't matter — Run sorts by Version() before
// applying. Two Steps with the same Version() are a programming error and
// the Runner will refuse to Run.
func (r *Runner) Register(steps ...Step) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, steps...)
}

// Run applies every Step whose Version() is greater than the tracker's
// recorded "highest applied" for this namespace. Steps run in version order;
// the first failure stops the run and the failure is bubbled up unwrapped.
//
// Run is safe to call multiple times against the same Runner — already-
// applied steps will be skipped. Newly-added steps will run on the next call.
//
// When a Lock is configured (WithLock), Run takes the lock first, runs a
// heartbeat goroutine, and Releases on exit. Lock loss mid-run cancels
// the in-flight step's context and returns ErrLockLost.
func (r *Runner) Run(ctx context.Context) error {
	if r.lock == nil {
		return r.runUnlocked(ctx)
	}
	return r.runLocked(ctx)
}

// runUnlocked is the original single-replica path. Kept inline here so
// the locked variant can call it after acquiring the lock with a
// cancel-on-lock-loss ctx.
func (r *Runner) runUnlocked(ctx context.Context) error {
	r.mu.Lock()
	steps := append([]Step(nil), r.steps...)
	r.mu.Unlock()

	if err := assertUniqueVersions(steps); err != nil {
		return err
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].Version() < steps[j].Version() })

	current, err := r.tracker.AppliedVersion(ctx, r.namespace)
	if err != nil {
		return fmt.Errorf("bootstrap[%s]: load applied version: %w", r.namespace, err)
	}

	for _, s := range steps {
		if s.Version() <= current {
			r.recordSkip(ctx, s)
			continue
		}
		started := time.Now()
		if err := s.Run(ctx); err != nil {
			r.recordFailure(ctx, s, err)
			return fmt.Errorf("bootstrap[%s] step %d %q failed after %s: %w",
				r.namespace, s.Version(), s.Name(), time.Since(started), err)
		}
		if err := r.tracker.MarkApplied(ctx, r.namespace, s.Version(), s.Name()); err != nil {
			r.recordFailure(ctx, s, err)
			return fmt.Errorf("bootstrap[%s] step %d %q applied but tracker write failed: %w",
				r.namespace, s.Version(), s.Name(), err)
		}
		r.recordApplied(ctx, s, time.Since(started))
		current = s.Version()
	}
	return nil
}

// runLocked acquires the configured lock, starts a heartbeat goroutine
// that cancels stepCtx on Renew failure, and runs the unlocked path
// against stepCtx. The lock is always Released — even on error.
func (r *Runner) runLocked(ctx context.Context) error {
	ttl := r.lockTTL
	if ttl <= 0 {
		ttl = defaultLockTTL
	}
	handle, err := r.acquireLock(ctx, ttl)
	if err != nil {
		return err
	}
	r.recordLock(ctx, EventLockAcquired, handle.FencingToken(), nil)

	stepCtx, cancel := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	heartbeatExit := make(chan error, 1)
	go r.heartbeat(stepCtx, handle, ttl/3, cancel, heartbeatDone, heartbeatExit)

	runErr := r.runUnlocked(stepCtx)
	cancel()        // stop the heartbeat
	<-heartbeatDone // wait for it to drain

	// Release with a fresh ctx — the parent may already be cancelled
	// (lock loss path), but we still want to attempt graceful release.
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer releaseCancel()
	relErr := handle.Release(releaseCtx)

	// Decide which error to surface. Priority: lock loss > step error >
	// release error. Lock-loss wraps so callers can errors.Is(ErrLockLost).
	var hbErr error
	select {
	case hbErr = <-heartbeatExit:
	default:
	}
	if hbErr != nil && errors.Is(hbErr, ErrLockLost) {
		r.recordLock(ctx, EventLockLost, handle.FencingToken(), hbErr)
		return fmt.Errorf("bootstrap[%s]: %w", r.namespace, hbErr)
	}
	r.recordLock(ctx, EventLockReleased, handle.FencingToken(), relErr)
	if runErr != nil {
		return runErr
	}
	if relErr != nil {
		return fmt.Errorf("bootstrap[%s]: lock release: %w", r.namespace, relErr)
	}
	return nil
}

// acquireLock encapsulates the blocking-vs-fail-fast contention policy.
func (r *Runner) acquireLock(ctx context.Context, ttl time.Duration) (lock.Handle, error) {
	for {
		h, err := r.lock.TryAcquire(ctx, r.lockKey, ttl)
		if err == nil {
			return h, nil
		}
		if !errors.Is(err, ErrLocked) {
			return nil, fmt.Errorf("bootstrap[%s]: lock acquire: %w", r.namespace, err)
		}
		// Contended.
		r.recordLock(ctx, EventLockContended, 0, nil)
		if !r.lockBlocking {
			return nil, fmt.Errorf("bootstrap[%s]: %w", r.namespace, ErrLocked)
		}
		backoff := r.lockBackoff
		if backoff <= 0 {
			backoff = defaultLockBackoff
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
}

// heartbeat fires Renew on every interval until ctx is done. On the
// first Renew error it cancels parent work via cancelStep and posts the
// error onto exit (non-blocking). done is closed when the goroutine
// exits.
func (r *Runner) heartbeat(ctx context.Context, h lock.Handle, interval time.Duration, cancelStep context.CancelFunc, done chan<- struct{}, exit chan<- error) {
	defer close(done)
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.safeRenew(ctx, h); err != nil {
				select {
				case exit <- err:
				default:
				}
				cancelStep()
				return
			}
		}
	}
}

// safeRenew calls h.Renew guarded by a recover. Lock is a pluggable SPI —
// third-party backends (redis, postgres advisory, a custom etcd variant)
// are expected — and this heartbeat goroutine has no caller to propagate
// a panic to: an unrecovered panic in ANY goroutine is process-fatal in
// Go, so a bug in one operator-supplied Renew implementation would take
// down the entire server mid-boot. A panic means we no longer know
// whether the lease is actually held, so — mirroring an ordinary Renew
// failure — it is folded into ErrLockLost: fail closed and cancel the
// in-flight step rather than silently carrying on under an uncertain lock.
func (r *Runner) safeRenew(ctx context.Context, h lock.Handle) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Error("bootstrap lock heartbeat panicked, treating lease as lost",
				"namespace", r.namespace, "key", r.lockKey, "panic", rec)
			err = fmt.Errorf("%w: heartbeat panic: %v", ErrLockLost, rec)
		}
	}()
	return h.Renew(ctx)
}

// EventLock* are the audit event-type names the Runner emits for lock
// lifecycle. They mirror audit.EventBootstrapLock* so callers don't need
// the audit package just to wire WithRecorder.
type lockEventType string

const (
	EventLockAcquired  lockEventType = "bootstrap_lock_acquired"
	EventLockReleased  lockEventType = "bootstrap_lock_released"
	EventLockLost      lockEventType = "bootstrap_lock_lost"
	EventLockContended lockEventType = "bootstrap_lock_contended"
)

func (r *Runner) recordLock(ctx context.Context, t lockEventType, token uint64, err error) {
	switch t {
	case EventLockAcquired:
		r.logger.Info("bootstrap lock acquired", "namespace", r.namespace, "key", r.lockKey, "fencing_token", token)
	case EventLockReleased:
		r.logger.Info("bootstrap lock released", "namespace", r.namespace, "key", r.lockKey, "fencing_token", token, "error", err)
	case EventLockLost:
		r.logger.Error("bootstrap lock lost", "namespace", r.namespace, "key", r.lockKey, "fencing_token", token, "error", err)
	case EventLockContended:
		r.logger.Info("bootstrap lock contended", "namespace", r.namespace, "key", r.lockKey)
	}
	if r.recorder == nil {
		return
	}
	outcome := audit.OutcomeSuccess
	reason := fmt.Sprintf("namespace=%s key=%s token=%d", r.namespace, r.lockKey, token)
	var et audit.EventType
	switch t {
	case EventLockAcquired:
		et = audit.EventBootstrapLockAcquired
	case EventLockReleased:
		et = audit.EventBootstrapLockReleased
		if err != nil {
			outcome = audit.OutcomeFailure
			reason += " err=" + err.Error()
		}
	case EventLockLost:
		et = audit.EventBootstrapLockLost
		outcome = audit.OutcomeFailure
		if err != nil {
			reason += " err=" + err.Error()
		}
	case EventLockContended:
		et = audit.EventBootstrapLockContended
	}
	r.recorder.Record(ctx, &audit.Event{
		Type: et, Outcome: outcome, Timestamp: time.Now().UTC(), Reason: reason,
	})
}

func assertUniqueVersions(steps []Step) error {
	seen := make(map[int]string, len(steps))
	for _, s := range steps {
		if prev, ok := seen[s.Version()]; ok {
			return fmt.Errorf("bootstrap: duplicate step version %d (%q and %q)", s.Version(), prev, s.Name())
		}
		seen[s.Version()] = s.Name()
	}
	return nil
}

func (r *Runner) recordApplied(ctx context.Context, s Step, took time.Duration) {
	r.logger.Info("bootstrap step applied", "namespace", r.namespace, "version", s.Version(), "name", s.Name(), "duration_ms", took.Milliseconds())
	if r.recorder != nil {
		r.recorder.Record(ctx, &audit.Event{
			Type: audit.EventBootstrapStepApplied, Outcome: audit.OutcomeSuccess,
			Timestamp: time.Now().UTC(),
			Reason:    fmt.Sprintf("namespace=%s version=%d name=%s", r.namespace, s.Version(), s.Name()),
		})
	}
}

func (r *Runner) recordSkip(ctx context.Context, s Step) {
	r.logger.Info("bootstrap step already applied — skipped", "namespace", r.namespace, "version", s.Version(), "name", s.Name())
	if r.recorder != nil {
		r.recorder.Record(ctx, &audit.Event{
			Type: audit.EventBootstrapStepSkipped, Outcome: audit.OutcomeSuccess,
			Timestamp: time.Now().UTC(),
			Reason:    fmt.Sprintf("namespace=%s version=%d name=%s", r.namespace, s.Version(), s.Name()),
		})
	}
}

func (r *Runner) recordFailure(ctx context.Context, s Step, err error) {
	r.logger.Error("bootstrap step failed", "namespace", r.namespace, "version", s.Version(), "name", s.Name(), "error", err)
	if r.recorder != nil {
		r.recorder.Record(ctx, &audit.Event{
			Type: audit.EventBootstrapStepFailed, Outcome: audit.OutcomeFailure,
			Timestamp: time.Now().UTC(),
			Reason:    fmt.Sprintf("namespace=%s version=%d name=%s err=%s", r.namespace, s.Version(), s.Name(), err.Error()),
		})
	}
}
