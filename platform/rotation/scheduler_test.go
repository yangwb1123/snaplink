package rotation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core/corecredential"
)

// waitForEvent drains ch until outcome is seen or the timeout elapses,
// forwarding any other event so a caller chaining multiple waits doesn't
// lose them.
func waitForEvent(t *testing.T, ch <-chan Event, outcome string, timeout time.Duration) Event {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case e := <-ch:
			if e.Outcome == outcome {
				return e
			}
		case <-deadline:
			t.Fatalf("timed out waiting for a %q event", outcome)
		}
	}
}

func newTestScheduler(t *testing.T, reg *Registry, opts ...SchedulerOption) (*Scheduler, chan Event) {
	t.Helper()
	events := make(chan Event, 16)
	opts = append(opts, WithEventHook(func(e Event) { events <- e }), WithSchedulerTick(5*time.Millisecond))
	sched := NewScheduler(reg, opts...)
	return sched, events
}

// TestScheduler_RotatesOnSchedule drives a real Start/Stop ticker loop (as
// opposed to registry_test.go's synchronous unit tests) and proves a due
// rotation fires an EventRotated with the new version.
func TestScheduler_RotatesOnSchedule(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	rotator := &fakeRotator{}
	if err := reg.Register(rotator, 10*time.Millisecond); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sched, events := newTestScheduler(t, reg)

	ctx, cancel := context.WithCancel(context.Background())
	done := sched.Start(ctx)

	e := waitForEvent(t, events, EventRotated, time.Second)
	if e.Meta.Version != 1 {
		t.Fatalf("rotated meta version = %d, want 1", e.Meta.Version)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop on ctx cancel")
	}
}

// TestScheduler_FailureKeepsOldCredentialServingAndRetries is the framework's
// central safety property (spec Edge Cases: "rotation failure must never
// leave zero usable credentials"): a failing Rotate must (1) emit
// EventRotateFailed carrying the error, (2) leave the previously-active
// version wholly intact, and (3) retry — a later successful Rotate then
// demotes that SAME still-serving version.
func TestScheduler_FailureKeepsOldCredentialServingAndRetries(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	seed := corecredential.CredentialMeta{ID: "seed/v1", Type: testCredType, Version: 1, Status: corecredential.CredentialStatusActive}
	boom := errors.New("boom")
	// A generous overlap keeps the demoted seed in "retiring" (rather than
	// being swept to "retired" on a later tick) for the whole assertion
	// window below — this test is about the DEMOTION transition, not
	// eventual retirement (covered by TestScheduler_RetiresAfterOverlapWindow).
	rotator := &seededRotator{fakeRotator: fakeRotator{version: 1, failErr: boom, overlap: time.Hour}, meta: seed}
	if err := reg.Register(rotator, 10*time.Millisecond); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sched, events := newTestScheduler(t, reg, WithRetryBackoff(5*time.Millisecond, 20*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sched.Start(ctx)

	failEvt := waitForEvent(t, events, EventRotateFailed, time.Second)
	if !errors.Is(failEvt.Err, boom) {
		t.Fatalf("failure event Err = %v, want %v", failEvt.Err, boom)
	}

	// The seed version must still be the one and only tracked active
	// credential — a failed Rotate must not have cleared or replaced it.
	inv := sched.Inventory()
	if len(inv) != 1 || inv[0].ID != seed.ID || inv[0].Version != 1 {
		t.Fatalf("Inventory() after a failed rotation = %+v, want only the untouched seed version", inv)
	}

	// fakeRotator.failErr was consumed by the first attempt, so the RETRY
	// (scheduled via the backoff above) succeeds and demotes the seed.
	rotEvt := waitForEvent(t, events, EventRotated, time.Second)
	if rotEvt.Meta.Version != 2 {
		t.Fatalf("post-retry rotation version = %d, want 2", rotEvt.Meta.Version)
	}
	inv = sched.Inventory()
	var sawRetiringSeed bool
	for _, e := range inv {
		if e.ID == seed.ID && e.Status == corecredential.CredentialStatusRetiring {
			sawRetiringSeed = true
		}
	}
	if !sawRetiringSeed {
		t.Fatalf("Inventory() after the retry succeeded = %+v, want the seed version demoted to retiring", inv)
	}
}

// TestScheduler_RetiresAfterOverlapWindow proves a demoted version drops out
// of the live inventory once its overlap window elapses, and that the store
// (a real MemoryCredentialStatusStore, not a mock, per repo convention)
// observes both the "retiring" and the final "retired" transition.
func TestScheduler_RetiresAfterOverlapWindow(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	// interval MUST exceed overlap: the registry tracks a single "retiring"
	// slot per credential type, so a rotation firing before the PRIOR
	// overlap window closes would overwrite it (that demoted version would
	// then never retire) — not a bug this test is exercising.
	rotator := &fakeRotator{overlap: 10 * time.Millisecond}
	if err := reg.Register(rotator, 30*time.Millisecond); err != nil {
		t.Fatalf("Register: %v", err)
	}
	store := newFakeStatusStore()
	sched, events := newTestScheduler(t, reg, WithStatusStore(store))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sched.Start(ctx)

	waitForEvent(t, events, EventRotated, time.Second) // v1 becomes active
	waitForEvent(t, events, EventRotated, time.Second) // v2 demotes v1 into retiring

	if got := store.status(testCredType, "test_cred/v1"); got != corecredential.CredentialStatusRetiring {
		t.Fatalf("store status for v1 after demotion = %q, want retiring", got)
	}

	waitForEvent(t, events, EventRetired, time.Second)
	if got := store.status(testCredType, "test_cred/v1"); got != corecredential.CredentialStatusRetired {
		t.Fatalf("store status for v1 after the overlap window closed = %q, want retired", got)
	}

	inv := sched.Inventory()
	for _, e := range inv {
		if e.ID == "test_cred/v1" {
			t.Fatalf("Inventory() still lists the retired version: %+v", inv)
		}
	}
}

// fakeStatusStore is a tiny corecredential.CredentialStatusStore double used
// only to observe status transitions synchronously in tests; the real
// backend (exercised elsewhere) is
// infrastructure/defaultimpl/memorystorecredential.MemoryCredentialStatusStore
// — kept out of this package to avoid an upward/test-only import.
type fakeStatusStore struct {
	mu   chan struct{} // 1-buffered mutex substitute (avoids importing sync just for this)
	rows map[string]corecredential.CredentialMeta
}

func newFakeStatusStore() *fakeStatusStore {
	s := &fakeStatusStore{mu: make(chan struct{}, 1), rows: map[string]corecredential.CredentialMeta{}}
	s.mu <- struct{}{}
	return s
}

func (s *fakeStatusStore) key(t corecredential.CredentialType, id string) string { return string(t) + "|" + id }

func (s *fakeStatusStore) Upsert(_ context.Context, meta corecredential.CredentialMeta) error {
	<-s.mu
	s.rows[s.key(meta.Type, meta.ID)] = meta
	s.mu <- struct{}{}
	return nil
}

func (s *fakeStatusStore) Get(_ context.Context, t corecredential.CredentialType, id string) (corecredential.CredentialMeta, error) {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	m, ok := s.rows[s.key(t, id)]
	if !ok {
		return corecredential.CredentialMeta{}, corecredential.ErrCredentialNotFound
	}
	return m, nil
}

func (s *fakeStatusStore) ListByType(_ context.Context, t corecredential.CredentialType) ([]corecredential.CredentialMeta, error) {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	var out []corecredential.CredentialMeta
	for _, m := range s.rows {
		if m.Type == t {
			out = append(out, m)
		}
	}
	return out, nil
}

func (s *fakeStatusStore) UpdateStatus(_ context.Context, t corecredential.CredentialType, id string, status corecredential.CredentialStatus) error {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	key := s.key(t, id)
	m, ok := s.rows[key]
	if !ok {
		return corecredential.ErrCredentialNotFound
	}
	m.Status = status
	s.rows[key] = m
	return nil
}

func (s *fakeStatusStore) status(t corecredential.CredentialType, id string) corecredential.CredentialStatus {
	m, err := s.Get(context.Background(), t, id)
	if err != nil {
		return ""
	}
	return m.Status
}

var _ corecredential.CredentialStatusStore = (*fakeStatusStore)(nil)
