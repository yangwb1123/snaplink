package bootstrap_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/snaplink/sso/audit"
	ssobootstrap "github.com/snaplink/sso/ssoclient/bootstrap"
)

// captureLogger records every Info/Error call so tests can assert that
// the runner threaded its logs through the WithLogger pipe.
type captureLogger struct {
	mu     sync.Mutex
	events []string
}

func (l *captureLogger) Info(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, "INFO:"+msg)
}
func (l *captureLogger) Error(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, "ERROR:"+msg)
}

func (l *captureLogger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

func TestNew_WithLogger_WiresIntoRunner(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	log := &captureLogger{}
	bs, err := ssobootstrap.New("test-app", statePath, ssobootstrap.WithLogger(log))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = bs.Close() }()

	bs.Register(ssobootstrap.StepFunc("seed", 1, func(context.Context) error { return nil }))
	if err := bs.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if log.count() == 0 {
		t.Error("captureLogger saw no events — WithLogger did not flow to the underlying Runner")
	}
}

func TestNew_WithRecorder_EmitsAuditEvents(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	bs, err := ssobootstrap.New("test-app-2", statePath, ssobootstrap.WithRecorder(rec))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = bs.Close() }()

	bs.Register(ssobootstrap.StepFunc("done", 1, func(context.Context) error { return nil }))
	if err := bs.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The Runner emits bootstrap_step_applied on a successful first run.
	events, _ := sink.Query(context.Background(), audit.Query{})
	if len(events) == 0 {
		t.Error("recorder saw no events — WithRecorder did not flow to the underlying Runner")
	}
}

func TestNew_WithRecorder_AlsoEmitsFailureEvents(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	bs, _ := ssobootstrap.New("test-app-3", statePath, ssobootstrap.WithRecorder(rec))
	defer func() { _ = bs.Close() }()

	bs.Register(ssobootstrap.StepFunc("broken", 1, func(context.Context) error {
		return errors.New("intentional")
	}))
	// Failure here is expected — we want to verify the recorder still
	// captured the bootstrap_step_failed event.
	_ = bs.Run(context.Background())

	events, _ := sink.Query(context.Background(), audit.Query{Outcome: audit.OutcomeFailure})
	if len(events) == 0 {
		t.Error("recorder saw no failure events — Runner should emit bootstrap_step_failed on Step error")
	}
}

func TestNew_BothOptions_Compose(t *testing.T) {
	// Wire BOTH WithLogger and WithRecorder; both must take effect.
	statePath := filepath.Join(t.TempDir(), "state.json")
	log := &captureLogger{}
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	bs, err := ssobootstrap.New("compose-app", statePath,
		ssobootstrap.WithLogger(log),
		ssobootstrap.WithRecorder(rec),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = bs.Close() }()
	bs.Register(ssobootstrap.StepFunc("ok", 1, func(context.Context) error { return nil }))
	_ = bs.Run(context.Background())

	if log.count() == 0 {
		t.Error("logger not threaded")
	}
	events, _ := sink.Query(context.Background(), audit.Query{})
	if len(events) == 0 {
		t.Error("recorder not threaded")
	}
}
