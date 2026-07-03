package dr

import (
	"sync"
	"time"
)

// Recovery outcome labels recorded in RecoveryRecord.Outcome. A failed
// recovery is STILL recorded — an aborted drill's duration is exactly the
// number an operator needs when tuning the RTO target.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// DefaultRTOHistory bounds the retained measured-RTO records when the
// caller passes keep <= 0. Small on purpose: the history is an operator
// report (admin DR status), not a time series — Prometheus holds the trend.
const DefaultRTOHistory = 32

// RecoveryRecord is one completed, timed recovery operation — a measured
// RTO data point.
type RecoveryRecord struct {
	Operation       string    `json:"operation"`
	StartedAt       time.Time `json:"started_at"`
	DurationSeconds float64   `json:"duration_seconds"`
	Outcome         string    `json:"outcome"`
}

// RecoveryTimeTracker times recovery operations (snapshot restore, replica
// promotion, DR drills) and retains a bounded history of measured RTOs.
// Safe for concurrent use.
type RecoveryTimeTracker struct {
	mu      sync.Mutex
	keep    int
	history []RecoveryRecord // oldest first
	now     func() time.Time
}

// NewRecoveryTimeTracker returns a tracker retaining the last keep records
// (keep <= 0 uses DefaultRTOHistory).
func NewRecoveryTimeTracker(keep int) *RecoveryTimeTracker {
	if keep <= 0 {
		keep = DefaultRTOHistory
	}
	return &RecoveryTimeTracker{keep: keep, now: time.Now}
}

// RecoveryTimer is one in-flight timed recovery operation.
type RecoveryTimer struct {
	tracker   *RecoveryTimeTracker
	operation string
	started   time.Time
}

// Start begins timing one recovery operation. Call Stop on the returned
// timer when the operation completes (or aborts).
func (t *RecoveryTimeTracker) Start(operation string) *RecoveryTimer {
	return &RecoveryTimer{tracker: t, operation: operation, started: t.now()}
}

// Stop ends the measurement and records it; err != nil records a failed
// recovery. Returns the recorded data point.
func (rt *RecoveryTimer) Stop(err error) RecoveryRecord {
	outcome := OutcomeSuccess
	if err != nil {
		outcome = OutcomeFailure
	}
	rec := RecoveryRecord{
		Operation:       rt.operation,
		StartedAt:       rt.started.UTC(),
		DurationSeconds: rt.tracker.now().Sub(rt.started).Seconds(),
		Outcome:         outcome,
	}
	rt.tracker.record(rec)
	return rec
}

func (t *RecoveryTimeTracker) record(rec RecoveryRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.history = append(t.history, rec)
	if len(t.history) > t.keep {
		// Re-slice into a fresh backing array so the dropped head can be
		// collected instead of pinning the old array forever.
		t.history = append([]RecoveryRecord(nil), t.history[len(t.history)-t.keep:]...)
	}
}

// History returns a copy of the retained records, oldest first.
func (t *RecoveryTimeTracker) History() []RecoveryRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]RecoveryRecord, len(t.history))
	copy(out, t.history)
	return out
}

// LastRecoverySeconds returns the most recent measured recovery duration.
// ok is false when no recovery has been timed yet.
func (t *RecoveryTimeTracker) LastRecoverySeconds() (float64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.history) == 0 {
		return 0, false
	}
	return t.history[len(t.history)-1].DurationSeconds, true
}
