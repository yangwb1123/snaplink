package degradation

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProbe is an injectable store probe: the verdict is switchable at runtime
// and a "hung" mode simulates a store that never answers (the driver's per-probe
// deadline must cut it and fail open).
type fakeProbe struct {
	mu     sync.Mutex
	calls  int
	result Health
	hung   bool
}

func (f *fakeProbe) check(ctx context.Context) Health {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.hung {
		<-ctx.Done()
		return HealthUnknown
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.result
}

func (f *fakeProbe) set(h Health) {
	f.mu.Lock()
	f.result = h
	f.mu.Unlock()
}

func (f *fakeProbe) setHung(v bool) {
	f.mu.Lock()
	f.hung = v
	f.mu.Unlock()
}

// waitMode polls m until it reaches want or the deadline fires.
func waitMode(t *testing.T, m *Manager, want Mode, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.Mode() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("mode did not reach %q (stayed %q)", want, m.Mode())
}

// assertModeStays fails if the mode moves away from want within dur.
func assertModeStays(t *testing.T, m *Manager, want Mode, dur time.Duration) {
	t.Helper()
	time.Sleep(dur)
	if got := m.Mode(); got != want {
		t.Fatalf("mode = %q, want %q", got, want)
	}
}

// waitCalls waits until the probe has been invoked at least want times.
func waitCalls(t *testing.T, p *fakeProbe, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		n := p.calls
		p.mu.Unlock()
		if n >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	t.Fatalf("probe called %d times, want >= %d", p.calls, want)
}

// startDriver runs d until the test ends; the deferred cancel+wait is the
// standard graceful-shutdown shape every test shares.
func startDriver(t *testing.T, d *Driver) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := d.Run(ctx)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("driver did not stop after cancel")
		}
	})
}

func TestDriver_StoreLossDrivesReadOnlyAndRecoveryRestoresBaseline(t *testing.T) {
	m := NewManager(ModeNormal)
	p := &fakeProbe{result: HealthHealthy}
	d := NewDriver(m, ModeNormal,
		[]Probe{{Name: "sqlite-identity-clients", Check: p.check}},
		10*time.Millisecond, 30*time.Millisecond, nil)
	if d == nil {
		t.Fatal("NewDriver returned nil for a valid manager")
	}
	startDriver(t, d)

	waitMode(t, m, ModeNormal, time.Second) // immediate sweep with a healthy store
	p.set(HealthUnhealthy)
	waitMode(t, m, ModeReadOnly, 2*time.Second)

	p.set(HealthHealthy)
	waitMode(t, m, ModeNormal, 2*time.Second) // recovery returns to the baseline
}

func TestDriver_DegradeReasonNamesStore(t *testing.T) {
	m := NewManager(ModeNormal)
	var mu sync.Mutex
	var reasons []string
	m.OnChange(func(_ context.Context, _, _ Mode, reason string) {
		mu.Lock()
		reasons = append(reasons, reason)
		mu.Unlock()
	})
	p := &fakeProbe{result: HealthHealthy}
	d := NewDriver(m, ModeNormal,
		[]Probe{{Name: "sqlite-identity-clients", Check: p.check}},
		5*time.Millisecond, 20*time.Millisecond, nil)
	startDriver(t, d)

	p.set(HealthUnhealthy)
	waitMode(t, m, ModeReadOnly, time.Second)

	mu.Lock()
	defer mu.Unlock()
	if len(reasons) == 0 || !strings.Contains(reasons[0], "sqlite-identity-clients") {
		t.Fatalf("degrade reasons %v do not name the lost store", reasons)
	}
}

func TestDriver_ProbeFlappingDoesNotTransition(t *testing.T) {
	m := NewManager(ModeNormal)
	p := &fakeProbe{result: HealthHealthy}
	d := NewDriver(m, ModeNormal,
		[]Probe{{Name: "flaky-store", Check: p.check}},
		5*time.Millisecond, 100*time.Millisecond, nil)
	startDriver(t, d)

	// One brief unhealthy burst (two sweeps), then healthy again: the loss
	// window never reaches the grace period, so the mode must not move.
	p.set(HealthUnhealthy)
	waitCalls(t, p, 2)
	p.set(HealthHealthy)
	assertModeStays(t, m, ModeNormal, 150*time.Millisecond)
}

func TestDriver_ProbeIndeterminateIsFailOpen(t *testing.T) {
	m := NewManager(ModeNormal)
	p := &fakeProbe{result: HealthUnknown}
	d := NewDriver(m, ModeNormal,
		[]Probe{{Name: "probe-broken", Check: p.check}},
		5*time.Millisecond, 20*time.Millisecond, nil)
	startDriver(t, d)

	// An indeterminate verdict (probe infrastructure error) must never count
	// toward a read_only transition.
	assertModeStays(t, m, ModeNormal, 100*time.Millisecond)
}

func TestDriver_HungProbeTimesOutFailOpen(t *testing.T) {
	m := NewManager(ModeNormal)
	p := &fakeProbe{result: HealthHealthy, hung: true}
	d := NewDriver(m, ModeNormal,
		[]Probe{{Name: "hung-store", Check: p.check}},
		10*time.Millisecond, 20*time.Millisecond, nil)
	startDriver(t, d)

	// The per-probe deadline cuts the hung probe; the timeout verdict is
	// HealthUnknown (fail-open), so the mode must stay normal.
	assertModeStays(t, m, ModeNormal, 300*time.Millisecond)
}

func TestDriver_OperatorOverrideWinsUntilBaselineReturn(t *testing.T) {
	m := NewManager(ModeNormal)
	p := &fakeProbe{result: HealthHealthy}
	d := NewDriver(m, ModeNormal,
		[]Probe{{Name: "sqlite-tenant", Check: p.check}},
		5*time.Millisecond, 20*time.Millisecond, nil)
	startDriver(t, d)

	p.set(HealthUnhealthy)
	waitMode(t, m, ModeReadOnly, time.Second)

	// The operator lifts the posture to maintenance; the driver must not fight
	// a non-baseline mode.
	if _, err := m.SetMode(context.Background(), ModeMaintenance, "operator drill"); err != nil {
		t.Fatalf("SetMode(maintenance): %v", err)
	}
	assertModeStays(t, m, ModeMaintenance, 100*time.Millisecond)

	// Returning to the baseline while the store is still lost re-arms the
	// invariant: the driver re-asserts read_only.
	if _, err := m.SetMode(context.Background(), ModeNormal, "operator lift"); err != nil {
		t.Fatalf("SetMode(normal): %v", err)
	}
	waitMode(t, m, ModeReadOnly, time.Second)
}

func TestDriver_ManualReadOnlyIsNotAutoRestored(t *testing.T) {
	m := NewManager(ModeNormal)
	p := &fakeProbe{result: HealthHealthy}
	d := NewDriver(m, ModeNormal,
		[]Probe{{Name: "sqlite-tenant", Check: p.check}},
		5*time.Millisecond, 20*time.Millisecond, nil)
	startDriver(t, d)

	if _, err := m.SetMode(context.Background(), ModeReadOnly, "operator"); err != nil {
		t.Fatalf("SetMode(read_only): %v", err)
	}
	// A read_only the driver did not set is never auto-restored, even with
	// healthy stores.
	assertModeStays(t, m, ModeReadOnly, 100*time.Millisecond)
}

func TestDriver_InvalidBaselineFallsBackToNormal(t *testing.T) {
	m := NewManager(ModeNormal)
	p := &fakeProbe{result: HealthHealthy}
	d := NewDriver(m, "bogus",
		[]Probe{{Name: "sqlite-tenant", Check: p.check}},
		5*time.Millisecond, 20*time.Millisecond, nil)
	startDriver(t, d)

	p.set(HealthUnhealthy)
	waitMode(t, m, ModeReadOnly, time.Second)
	p.set(HealthHealthy)
	waitMode(t, m, ModeNormal, time.Second) // restores normal, never "bogus"
}

func TestDriver_DefaultsAndGracefulShutdown(t *testing.T) {
	m := NewManager(ModeNormal)
	d := NewDriver(m, ModeNormal,
		[]Probe{{Name: "sqlite-tenant", Check: func(context.Context) Health { return HealthHealthy }}},
		0, 0, nil)
	if d.Interval() != DefaultAutoInterval || d.Grace() != DefaultAutoGrace {
		t.Fatalf("defaults not applied: interval=%v grace=%v", d.Interval(), d.Grace())
	}
	if d.StoreCount() != 1 {
		t.Fatalf("StoreCount() = %d, want 1", d.StoreCount())
	}
	// Run must return promptly when ctx is canceled (graceful shutdown).
	ctx, cancel := context.WithCancel(context.Background())
	done := d.Run(ctx)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestDriver_NewDriverNilManager(t *testing.T) {
	if d := NewDriver(nil, ModeNormal, nil, 0, 0, nil); d != nil {
		t.Fatalf("NewDriver(nil mgr) = %v, want nil", d)
	}
}
