package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// degradation_wiring_test.go proves the auto read_only driver wiring:
// wireDegradation arms the driver (cancel/done pair + end-to-end transitions
// through the real Manager) exactly when degradation.enabled +
// auto_read_only_on_store_loss are set and a watchable store exists, and stays
// byte-identical (no driver, no goroutine) otherwise.

// fakePinger is a switchable StorageHealthSource.Ping.
type fakePinger struct {
	mu  sync.Mutex
	err error
}

func (f *fakePinger) ping(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *fakePinger) set(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

// waitDegMode polls the wired manager until it reaches want.
func waitDegMode(t *testing.T, m *sso.DegradationManager, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if string(m.Mode()) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("mode did not reach %q (stayed %q)", want, m.Mode())
}

// TestWireDegradation_ArmsAutoDriver proves the full wiring seam: with the
// intent flag set and a watchable storage source, wireDegradation arms the
// driver and a real store loss drives the manager to read_only (recovery
// returns to the configured initial_mode). The audit-* source shares the same
// ping closure but is excluded from the watchlist by the composition root.
func TestWireDegradation_ArmsAutoDriver(t *testing.T) {
	cfg := &config.Config{}
	cfg.Degradation.Enabled = true
	cfg.Degradation.InitialMode = "normal"
	cfg.Degradation.AutoReadOnlyOnStoreLoss = true
	cfg.Degradation.AutoReadOnly.Interval = 10 * time.Millisecond
	cfg.Degradation.AutoReadOnly.Grace = 20 * time.Millisecond

	pinger := &fakePinger{}
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	b.storageHealthSources = []sso.StorageHealthSource{
		{Name: "sqlite-identity-clients", Ping: pinger.ping},
		{Name: "audit-sqlite", Ping: pinger.ping},
	}
	if err := b.wireDegradation(); err != nil {
		t.Fatalf("wireDegradation: %v", err)
	}
	if b.degradationMgr == nil {
		t.Fatal("degradation manager not wired")
	}
	if b.autoReadOnlyCancel == nil || b.autoReadOnlyDone == nil {
		t.Fatal("auto read_only driver not armed (cancel/done pair missing)")
	}
	defer func() {
		b.autoReadOnlyCancel()
		select {
		case <-b.autoReadOnlyDone:
		case <-time.After(2 * time.Second):
			t.Error("auto driver did not stop after cancel")
		}
	}()

	// End-to-end: a lost store flips the manager to read_only; recovery
	// restores the configured initial_mode. Transitions fire through the same
	// Manager the admin dr/mode endpoint drives.
	pinger.set(errors.New("connection refused"))
	waitDegMode(t, b.degradationMgr, "read_only", 2*time.Second)
	pinger.set(nil)
	waitDegMode(t, b.degradationMgr, "normal", 2*time.Second)
}

// TestWireDegradation_FlagUnsetHasNoDriver — without the intent flag the
// degraded-service gate wires but no driver goroutine exists.
func TestWireDegradation_FlagUnsetHasNoDriver(t *testing.T) {
	cfg := &config.Config{}
	cfg.Degradation.Enabled = true
	cfg.Degradation.InitialMode = "normal"
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	b.storageHealthSources = []sso.StorageHealthSource{
		{Name: "sqlite-identity-clients", Ping: func(context.Context) error { return nil }},
	}
	if err := b.wireDegradation(); err != nil {
		t.Fatalf("wireDegradation: %v", err)
	}
	if b.degradationMgr == nil {
		t.Fatal("degradation manager not wired")
	}
	if b.autoReadOnlyCancel != nil || b.autoReadOnlyDone != nil {
		t.Fatal("auto driver armed without auto_read_only_on_store_loss")
	}
}

// TestWireDegradation_FlagSetButNoWatchableStore — a memory-only deployment
// that sets the intent flag for a future multi-store rollout must keep booting
// with no driver and no goroutine.
func TestWireDegradation_FlagSetButNoWatchableStore(t *testing.T) {
	cfg := &config.Config{}
	cfg.Degradation.Enabled = true
	cfg.Degradation.AutoReadOnlyOnStoreLoss = true
	b := &appBuilder{cfg: cfg, logger: quietLogger()} // no storage sources
	if err := b.wireDegradation(); err != nil {
		t.Fatalf("wireDegradation: %v", err)
	}
	if b.autoReadOnlyCancel != nil || b.autoReadOnlyDone != nil {
		t.Fatal("driver armed with no watchable store")
	}
}

// TestWireDegradation_BuildAppSecurityWithinBudget pins the hard line budget
// of the file hosting wireDegradation: the auto-driver seam must never push it
// over 500 lines (the maintainability gate enforces the same budget; this
// assertion keeps the failure local to the wiring change).
func TestWireDegradation_BuildAppSecurityWithinBudget(t *testing.T) {
	data, err := os.ReadFile("build_app_security.go")
	if err != nil {
		t.Fatalf("read build_app_security.go: %v", err)
	}
	if n := strings.Count(string(data), "\n"); n > 500 {
		t.Fatalf("build_app_security.go has %d lines, budget is 500", n)
	}
}
