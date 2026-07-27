package continuousverify_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/platform/lifecycle/continuousverify"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/trust"
)

// liveCfg decays a 1.0 score below the 0.6 floor after ~60 minutes.
func liveCfg() trust.DecayConfig {
	return trust.DecayConfig{Interval: 5 * time.Minute, Factor: 0.95, Floor: 0.6}
}

// seedSession creates a session in the REAL MemorySessionManager with a bound
// trust baseline (no mocks — MemorySessionManager is both the lister and the
// SessionTrustManager the agent drives).
func seedSession(t *testing.T, mgr *memorystoreidentity.MemorySessionManager, score float64, setAt time.Time) *core.Session {
	t.Helper()
	s, err := mgr.CreateWithMeta(context.Background(), "u1", core.SessionMeta{TrustScore: score, TrustSetAt: setAt})
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return s
}

func TestAgent_MarksBelowFloorSession(t *testing.T) {
	t.Parallel()
	mgr := memorystoreidentity.NewMemorySessionManager()
	base := time.Now().Add(-2 * time.Hour) // real ExpiresAt still far in the future
	stale := seedSession(t, mgr, 1.0, base)

	var events int32
	agent := continuousverify.NewAgent(mgr, mgr, liveCfg(),
		// Inject a clock 60min past the baseline so the decayed score is < floor.
		continuousverify.WithClock(func() time.Time { return base.Add(time.Hour) }),
		continuousverify.WithEventHook(func(continuousverify.Event) { atomic.AddInt32(&events, 1) }),
	)
	agent.Sweep(context.Background())

	got, err := mgr.Get(context.Background(), stale.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.StepUpRequired {
		t.Fatalf("below-floor session was not marked for step-up")
	}
	if atomic.LoadInt32(&events) != 1 {
		t.Fatalf("event hook fired %d times, want 1", events)
	}
}

func TestAgent_SkipsFreshAndNoSignalSessions(t *testing.T) {
	t.Parallel()
	mgr := memorystoreidentity.NewMemorySessionManager()
	base := time.Now().Add(-2 * time.Hour)
	fresh := seedSession(t, mgr, 1.0, base)           // decays but clock is AT base → still 1.0
	noSignal := seedSession(t, mgr, 0.0, time.Time{}) // legacy zero-value: fail-open

	agent := continuousverify.NewAgent(mgr, mgr, liveCfg(),
		continuousverify.WithClock(func() time.Time { return base }), // no elapsed decay
	)
	agent.Sweep(context.Background())

	for _, id := range []string{fresh.ID, noSignal.ID} {
		got, err := mgr.Get(context.Background(), id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if got.StepUpRequired {
			t.Fatalf("session %s was marked but should be left untouched (fail-open)", id)
		}
	}
}

func TestAgent_DisabledConfigIsInert(t *testing.T) {
	t.Parallel()
	mgr := memorystoreidentity.NewMemorySessionManager()
	base := time.Now().Add(-2 * time.Hour)
	s := seedSession(t, mgr, 1.0, base)

	// Zero (feature-off) cfg: even a would-be-stale session is never marked.
	agent := continuousverify.NewAgent(mgr, mgr, trust.DecayConfig{},
		continuousverify.WithClock(func() time.Time { return base.Add(time.Hour) }),
	)
	done := agent.Start(context.Background()) // must be inert / return closed channel
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("disabled agent Start did not return a closed channel")
	}
	agent.Sweep(context.Background())

	got, _ := mgr.Get(context.Background(), s.ID)
	if got.StepUpRequired {
		t.Fatalf("disabled agent marked a session")
	}
}

// failLister is a real (tiny) lister whose ListAll errors — used to prove the
// agent fails OPEN on a store outage (skips the sweep, never panics/wedges).
type failLister struct{}

func (failLister) ListAll(context.Context) ([]*core.Session, error) {
	return nil, errors.New("store down")
}

func TestAgent_FailOpenOnListError(t *testing.T) {
	t.Parallel()
	mgr := memorystoreidentity.NewMemorySessionManager()
	agent := continuousverify.NewAgent(failLister{}, mgr, liveCfg())
	// Must not panic; simply skips the pass.
	agent.Sweep(context.Background())
}

func TestAgent_StartStopLifecycle(t *testing.T) {
	t.Parallel()
	mgr := memorystoreidentity.NewMemorySessionManager()
	base := time.Now().Add(-2 * time.Hour)
	s := seedSession(t, mgr, 1.0, base)

	marked := make(chan struct{}, 1)
	agent := continuousverify.NewAgent(mgr, mgr, liveCfg(),
		continuousverify.WithSweepInterval(5*time.Millisecond),
		continuousverify.WithClock(func() time.Time { return base.Add(time.Hour) }),
		continuousverify.WithEventHook(func(continuousverify.Event) {
			select {
			case marked <- struct{}{}:
			default:
			}
		}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := agent.Start(ctx)
	select {
	case <-marked:
	case <-time.After(2 * time.Second):
		t.Fatalf("running agent never marked the stale session")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent loop did not exit after context cancel")
	}
	// Stop is idempotent / safe after cancel.
	agent.Stop()

	got, _ := mgr.Get(context.Background(), s.ID)
	if !got.StepUpRequired {
		t.Fatalf("running agent did not persist the step-up flag")
	}
}
