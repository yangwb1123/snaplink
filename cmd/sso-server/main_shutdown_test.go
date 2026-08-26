package main

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	configreload "github.com/yangwb1123/snaplink/config/reload"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestWaitLoop_ShutdownSignalReturnsNil(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	sigCh <- os.Interrupt

	if err := waitLoop(spi.NopLogger{}, sigCh, nil, errCh, nil); err != nil {
		t.Errorf("waitLoop() error = %v, want nil", err)
	}
}

func TestWaitLoop_ErrChReturnsError(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	boom := errors.New("boom")
	errCh <- boom

	if err := waitLoop(spi.NopLogger{}, sigCh, nil, errCh, nil); !errors.Is(err, boom) {
		t.Errorf("waitLoop() error = %v, want %v", err, boom)
	}
}

func TestWaitLoop_NilReloaderNeverSelectsHUP(t *testing.T) {
	// hupCh nil (as waitForShutdown builds it when reloader == nil) must
	// never be selected — the loop should keep waiting until the shutdown
	// channel fires, never panic or hang on a reload with a nil Reloader.
	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- waitLoop(spi.NopLogger{}, sigCh, nil, errCh, nil) }()

	select {
	case <-done:
		t.Fatal("waitLoop returned before any signal/error arrived")
	case <-time.After(20 * time.Millisecond):
	}
	sigCh <- os.Interrupt
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("waitLoop() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitLoop did not return after the shutdown signal")
	}
}

func TestWaitLoop_HUPTriggersReloadThenResumesWaiting(t *testing.T) {
	initial := &config.Config{Logging: config.LoggingConfig{Level: "info"}}
	// levelCh (not a plain shared variable) is the synchronization point
	// between the background waitLoop goroutine and this test goroutine —
	// a channel receive establishes happens-before, avoiding a data race on
	// a polled variable.
	levelCh := make(chan string, 1)
	reloader := configreload.New(initial, func(context.Context) (*config.Config, error) {
		return &config.Config{Logging: config.LoggingConfig{Level: "debug"}}, nil
	}, func(l string) { levelCh <- l })

	sigCh := make(chan os.Signal, 1)
	hupCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- waitLoop(spi.NopLogger{}, sigCh, hupCh, errCh, reloader) }()

	hupCh <- syscall.SIGHUP

	select {
	case level := <-levelCh:
		if level != "debug" {
			t.Errorf("setLogLevel hook got %q, want debug", level)
		}
	case <-time.After(time.Second):
		t.Fatal("reload was never applied")
	}

	// A SIGHUP must never cause the loop to return.
	select {
	case err := <-done:
		t.Fatalf("waitLoop returned %v after a SIGHUP — it must keep waiting", err)
	case <-time.After(20 * time.Millisecond):
	}

	sigCh <- os.Interrupt
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("waitLoop() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitLoop did not return after the shutdown signal")
	}
}

func TestApplyReload_ErrorDoesNotPanic(t *testing.T) {
	reloader := configreload.New(&config.Config{}, func(context.Context) (*config.Config, error) {
		return nil, errors.New("bad config")
	}, nil)
	// Must not panic; a reload failure is logged and swallowed so a bad
	// edit can never crash a running server via SIGHUP.
	applyReload(spi.NopLogger{}, reloader)
}

func TestCloseMemoryStoreReapers_NilServerIsNoOp(t *testing.T) {
	// buildApp always sets a.server, but closeMemoryStoreReapers must not
	// assume that — a nil server (e.g. mid-construction failure) must not
	// panic.
	closeMemoryStoreReapers(&app{})
}

func TestAddAuditCloserPreservesExistingClose(t *testing.T) {
	var order []string
	b := &appBuilder{externalAuditClose: func(context.Context) error {
		order = append(order, "existing")
		return nil
	}}
	b.addAuditCloser(func(context.Context) error {
		order = append(order, "new")
		return nil
	})
	if err := b.externalAuditClose(context.Background()); err != nil {
		t.Fatalf("close chain: %v", err)
	}
	if len(order) != 2 || order[0] != "new" || order[1] != "existing" {
		t.Fatalf("close order = %v; want [new existing]", order)
	}
}

func TestCloseMemoryStoreReapers_ClosesRunningReapersWithoutPanicking(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.OAuth.RefreshToken.ReapInterval = 5 * time.Millisecond
	cfg.OAuth.DeviceCode.ReapInterval = 5 * time.Millisecond
	cfg.OAuth.PAR.ReapInterval = 5 * time.Millisecond
	cfg.Security.JTIReplay.ReapInterval = 5 * time.Millisecond

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	// Give each reaper goroutine a moment to actually start ticking, then
	// close — this must stop every one cleanly (no goroutine leak, no
	// panic) even though the stores were never used for real traffic.
	time.Sleep(10 * time.Millisecond)
	closeMemoryStoreReapers(a)
	// Idempotent: a second close (mirroring a caller that shuts down
	// twice, e.g. a test harness plus a real signal) must not panic.
	closeMemoryStoreReapers(a)
}
