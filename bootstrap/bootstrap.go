package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/snaplink/sso/audit"
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

func (f *funcStep) Name() string                    { return f.name }
func (f *funcStep) Version() int                    { return f.version }
func (f *funcStep) Run(ctx context.Context) error   { return f.run(ctx) }

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

	mu    sync.Mutex
	steps []Step
}

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
func (r *Runner) Run(ctx context.Context) error {
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
