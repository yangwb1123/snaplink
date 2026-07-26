package anomaly

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/spi"
)

func TestWithQueueSize(t *testing.T) {
	r := &Runner{}
	WithQueueSize(100)(r)
	if r.queueSize != 100 {
		t.Errorf("expected queueSize 100, got %d", r.queueSize)
	}
}

func TestWithWorkers(t *testing.T) {
	r := &Runner{}
	WithWorkers(5)(r)
	if r.workers != 5 {
		t.Errorf("expected workers 5, got %d", r.workers)
	}
}

func TestWithInspectTimeout(t *testing.T) {
	r := &Runner{}
	timeout := 3 * time.Second
	WithInspectTimeout(timeout)(r)
	if r.inspectTimeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, r.inspectTimeout)
	}
}

func TestWithDropPolicy(t *testing.T) {
	r := &Runner{}
	WithDropPolicy(DropBlock)(r)
	if r.dropPolicy != DropBlock {
		t.Errorf("expected DropBlock, got %v", r.dropPolicy)
	}

	r2 := &Runner{}
	WithDropPolicy(DropNewest)(r2)
	if r2.dropPolicy != DropNewest {
		t.Errorf("expected DropNewest, got %v", r2.dropPolicy)
	}
}

func TestWithLogger(t *testing.T) {
	r := &Runner{}
	logger := spi.NopLogger{}
	WithLogger(logger)(r)
	if r.logger == nil {
		t.Error("expected non-nil logger")
	}
}

func TestDropPolicyConstants(t *testing.T) {
	if DropNewest != "drop_newest" {
		t.Errorf("expected DropNewest='drop_newest', got %q", DropNewest)
	}
	if DropBlock != "block" {
		t.Errorf("expected DropBlock='block', got %q", DropBlock)
	}
}

func TestRunner_CreatedWithOptions(t *testing.T) {
	r := NewRunner([]Detector{}, nil)
	if r != nil {
		t.Error("expected nil runner for empty detector list")
	}

	r = NewRunner([]Detector{&stubDetector{}}, &stubSink{})
	if r == nil {
		t.Fatal("expected non-nil runner")
	}
	if r.queueSize <= 0 {
		t.Errorf("expected positive default queue size, got %d", r.queueSize)
	}
	if r.workers <= 0 {
		t.Errorf("expected positive default workers, got %d", r.workers)
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityInfo != "info" {
		t.Errorf("expected 'info', got %q", SeverityInfo)
	}
	if SeverityWarn != "warn" {
		t.Errorf("expected 'warn', got %q", SeverityWarn)
	}
	if SeverityCritical != "critical" {
		t.Errorf("expected 'critical', got %q", SeverityCritical)
	}
}

func TestSignalZeroValue(t *testing.T) {
	var s Signal
	if s.Type != "" {
		t.Errorf("expected empty Type, got %q", s.Type)
	}
	if s.Severity != "" {
		t.Errorf("expected empty Severity, got %q", s.Severity)
	}
	if s.Score != 0 {
		t.Errorf("expected zero Score, got %d", s.Score)
	}
}

func TestLoginEventFields(t *testing.T) {
	e := LoginEvent{
		SubjectID: "user-1",
		ClientID:  "app-1",
		Provider:  "password",
		Outcome:   "success",
	}
	if e.SubjectID != "user-1" {
		t.Errorf("expected SubjectID 'user-1', got %q", e.SubjectID)
	}
	if e.ClientID != "app-1" {
		t.Errorf("expected ClientID 'app-1', got %q", e.ClientID)
	}
	if e.Provider != "password" {
		t.Errorf("expected Provider 'password', got %q", e.Provider)
	}
}

type stubDetector struct{}
func (s *stubDetector) Name() string { return "stub" }
func (s *stubDetector) Inspect(ctx context.Context, event *LoginEvent) ([]Signal, error) { return nil, nil }

type stubSink struct{}
func (s *stubSink) Name() string { return "stub" }
func (s *stubSink) Record(ctx context.Context, event *LoginEvent, anomaly Signal) error { return nil }
