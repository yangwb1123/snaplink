package continuousverify

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/trust"
)

type mockSessionManager struct {
	mu       sync.Mutex
	sessions []*core.Session
	stepUp   map[string]bool
}

func (m *mockSessionManager) ListAll(_ context.Context) ([]*core.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*core.Session, len(m.sessions))
	copy(out, m.sessions)
	return out, nil
}

func (m *mockSessionManager) MarkStepUp(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stepUp[sessionID] = true
	return nil
}

func (m *mockSessionManager) SetTrust(_ context.Context, _ string, _ float64, _ time.Time) error {
	return nil
}

func (m *mockSessionManager) addSession(s *core.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = append(m.sessions, s)
}

func newMockSessionManager() *mockSessionManager {
	return &mockSessionManager{
		sessions: make([]*core.Session, 0),
		stepUp:   make(map[string]bool),
	}
}

func TestNewAgent(t *testing.T) {
	mgr := newMockSessionManager()
	cfg := trust.DecayConfig{}

	agent := NewAgent(mgr, mgr, cfg)
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
}

func TestAgent_WithOptions(t *testing.T) {
	mgr := newMockSessionManager()
	cfg := trust.DecayConfig{}

	clock := func() time.Time { return time.Now() }

	agent := NewAgent(mgr, mgr, cfg,
		WithSweepInterval(10*time.Second),
		WithClock(clock),
	)
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
}

func TestAgent_SweepDoesNotPanicWithNoSessions(t *testing.T) {
	mgr := newMockSessionManager()
	cfg := trust.DecayConfig{}

	agent := NewAgent(mgr, mgr, cfg, WithClock(func() time.Time {
		return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	}))

	agent.Sweep(context.Background())
}

func TestAgent_SweepWithStepUpTriggered(t *testing.T) {
	mgr := newMockSessionManager()
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	mgr.addSession(&core.Session{
		ID:         "sess-1",
		UserID:     "user-1",
		TrustScore: 0.3,
		TrustSetAt: now.Add(-24 * time.Hour),
	})

	cfg := trust.DecayConfig{
		Interval: 12 * time.Hour,
		Factor:   0.5,
		Floor:    0.2,
		MinScore: 0.1,
	}

	eventCount := atomic.Int64{}
	agent := NewAgent(mgr, mgr, cfg,
		WithClock(func() time.Time { return now }),
		WithEventHook(func(e Event) {
			eventCount.Add(1)
		}),
	)

	agent.Sweep(context.Background())
	events := eventCount.Load()
	t.Logf("sweep events: %d", events)
}

func TestAgent_EventHookNil(t *testing.T) {
	mgr := newMockSessionManager()
	cfg := trust.DecayConfig{}

	agent := NewAgent(mgr, mgr, cfg, WithEventHook(nil))
	if agent == nil {
		t.Fatal("expected non-nil agent")
	}
}

func TestAgent_ConcurrentSweepIsSafe(t *testing.T) {
	mgr := newMockSessionManager()
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 10; i++ {
		mgr.addSession(&core.Session{
			ID:         "sess-" + itoa(i),
			UserID:     "user-" + itoa(i),
			TrustScore: 0.8,
			TrustSetAt: now.Add(-1 * time.Hour),
		})
	}

	cfg := trust.DecayConfig{
		Interval: 24 * time.Hour,
		Factor:   0.95,
		Floor:    0.3,
		MinScore: 0.1,
	}

	agent := NewAgent(mgr, mgr, cfg,
		WithClock(func() time.Time { return now }),
	)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			agent.Sweep(context.Background())
		}()
	}
	wg.Wait()
}

func itoa(n int) string {
	if n == 0 { return "0" }
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--; buf[i] = byte('0' + n%10); n /= 10
	}
	return string(buf[i:])
}
