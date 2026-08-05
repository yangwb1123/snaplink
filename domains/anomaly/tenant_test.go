package anomaly

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// tenantCapturingSink records the signals the runner delivers, so tests can
// assert the tenant backfill happened at the runner boundary.
type tenantCapturingSink struct {
	mu      sync.Mutex
	signals []Signal
}

func (s *tenantCapturingSink) Record(_ context.Context, _ *LoginEvent, a Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signals = append(s.signals, a)
	return nil
}

func (s *tenantCapturingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.signals)
}

// TestRunner_TenantBackfillReachesSink pins improvement-1's runner
// behavior: a detector that leaves Signal.TenantID empty inherits the
// event's tenant, and a detector that sets its own tenant keeps it.
func TestRunner_TenantBackfillReachesSink(t *testing.T) {
	t.Parallel()
	d := &recordingDetector{name: "d", cannedAnoms: []Signal{
		{Type: "impossible_travel", Severity: SeverityWarn, SubjectID: "alice"},
		{Type: "velocity_burst", Severity: SeverityInfo, SubjectID: "bob", TenantID: "detector-claimed"},
	}}
	sink := &tenantCapturingSink{}
	r := NewRunner([]Detector{d}, sink)
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Dispatch(context.Background(), &LoginEvent{TenantID: "t1", SubjectID: "alice"})

	waitFor(t, time.Second, func() bool { return sink.count() == 2 })
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.signals[0].TenantID != "t1" {
		t.Errorf("backfilled signal tenant = %q, want t1", sink.signals[0].TenantID)
	}
	if sink.signals[1].TenantID != "detector-claimed" {
		t.Errorf("detector-claimed tenant = %q, want detector-claimed (no override)", sink.signals[1].TenantID)
	}
}

// TestRunner_TenantMismatchThreatRefused pins the guard truth table's
// mismatch cell: a detector-claimed tenant that differs from the event's is
// refused (never executed) while the signal still reaches the sink.
func TestRunner_TenantMismatchThreatRefused(t *testing.T) {
	t.Parallel()
	d := &recordingDetector{name: "d", cannedAnoms: []Signal{
		{Type: "impossible_travel", Severity: SeverityWarn, SubjectID: "alice", TenantID: "t2"},
	}}
	sink := &tenantCapturingSink{}
	exec := &recordingThreatExecutor{}
	r := NewRunner([]Detector{d}, sink, WithThreatExecutor(exec))
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Dispatch(context.Background(), &LoginEvent{TenantID: "t1", SubjectID: "alice"})

	waitFor(t, time.Second, func() bool { return sink.count() == 1 })
	time.Sleep(50 * time.Millisecond)
	if exec.count() != 0 {
		t.Fatalf("mismatched-tenant signal executed %d threats, want 0", exec.count())
	}
}

// TestNewRecorderSink_TenantStamped pins improvement-3's audit stamp: a
// tenant-carrying event produces an audit event with TenantID and the
// tenant.id metadata; an empty tenant stays byte-identical to the legacy
// shape (no tenant fields at all).
func TestNewRecorderSink_TenantStamped(t *testing.T) {
	t.Parallel()
	auditSink := audit.NewMemorySink(10)
	rec := audit.New(auditSink)
	rs := NewRecorderSink(rec)
	if rs == nil {
		t.Fatal("NewRecorderSink(non-nil) must return a sink")
	}
	if err := rs.Record(context.Background(), &LoginEvent{TenantID: "t1", SubjectID: "alice"}, Signal{
		Type: "impossible_travel", Severity: SeverityWarn, SubjectID: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	events, _ := auditSink.Query(context.Background(), audit.Query{Type: audit.EventAnomalyDetected})
	if len(events) != 1 {
		t.Fatalf("anomaly events = %d, want 1", len(events))
	}
	if events[0].TenantID != "t1" {
		t.Errorf("audit event TenantID = %q, want t1", events[0].TenantID)
	}
	if got := events[0].Metadata["tenant.id"]; got != "t1" {
		t.Errorf("tenant.id meta = %q, want t1", got)
	}

	// Empty tenant: no tenant fields anywhere.
	if err := rs.Record(context.Background(), &LoginEvent{SubjectID: "bob"}, Signal{
		Type: "new_device", Severity: SeverityInfo, SubjectID: "bob",
	}); err != nil {
		t.Fatal(err)
	}
	events, _ = auditSink.Query(context.Background(), audit.Query{Type: audit.EventAnomalyDetected})
	if len(events) != 2 {
		t.Fatalf("anomaly events = %d, want 2", len(events))
	}
	// Query returns newest first; the tenant-less event is index 0.
	if events[0].TenantID != "" {
		t.Errorf("tenant-less event TenantID = %q, want empty", events[0].TenantID)
	}
	if _, ok := events[0].Metadata["tenant.id"]; ok {
		t.Errorf("tenant-less event carries tenant.id meta: %v", events[0].Metadata)
	}
}
