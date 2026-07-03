package dr

import (
	"errors"
	"testing"
	"time"
)

// stepClock returns a now func that advances by step on every call after
// the first, so tests measure a deterministic duration without a real
// sleep (avoids flaky timing-sensitive assertions).
func stepClock(start time.Time, step time.Duration) func() time.Time {
	first := true
	t := start
	return func() time.Time {
		if first {
			first = false
			return t
		}
		t = t.Add(step)
		return t
	}
}

func TestRecoveryTimeTracker_MeasuresDuration(t *testing.T) {
	tr := NewRecoveryTimeTracker(0)
	tr.now = stepClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 3*time.Second)

	timer := tr.Start("snapshot_restore")
	rec := timer.Stop(nil)

	if rec.Operation != "snapshot_restore" {
		t.Errorf("Operation = %q, want snapshot_restore", rec.Operation)
	}
	if rec.DurationSeconds != 3 {
		t.Errorf("DurationSeconds = %v, want 3", rec.DurationSeconds)
	}
	if rec.Outcome != OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", rec.Outcome, OutcomeSuccess)
	}

	last, ok := tr.LastRecoverySeconds()
	if !ok || last != 3 {
		t.Errorf("LastRecoverySeconds() = (%v, %v), want (3, true)", last, ok)
	}
}

func TestRecoveryTimeTracker_FailureOutcomeStillRecorded(t *testing.T) {
	tr := NewRecoveryTimeTracker(0)
	tr.now = stepClock(time.Now(), time.Second)

	timer := tr.Start("replica_promotion")
	rec := timer.Stop(errors.New("promotion failed"))

	if rec.Outcome != OutcomeFailure {
		t.Errorf("Outcome = %q, want %q", rec.Outcome, OutcomeFailure)
	}
	hist := tr.History()
	if len(hist) != 1 || hist[0].Outcome != OutcomeFailure {
		t.Errorf("History() = %+v, want one failed record", hist)
	}
}

func TestRecoveryTimeTracker_BoundedHistory(t *testing.T) {
	tr := NewRecoveryTimeTracker(2)
	tr.now = stepClock(time.Now(), time.Second)

	for i := 0; i < 3; i++ {
		tr.Start("op").Stop(nil)
	}

	hist := tr.History()
	if len(hist) != 2 {
		t.Fatalf("History() length = %d, want 2 (bounded by keep)", len(hist))
	}
	// Oldest-first: after dropping the first of 3, the survivors are
	// records #2 and #3 — confirm via increasing StartedAt.
	if !hist[1].StartedAt.After(hist[0].StartedAt) {
		t.Errorf("History() not oldest-first: %+v", hist)
	}
}

func TestNewRecoveryTimeTracker_DefaultKeep(t *testing.T) {
	tr := NewRecoveryTimeTracker(0)
	if tr.keep != DefaultRTOHistory {
		t.Errorf("keep = %d, want default %d", tr.keep, DefaultRTOHistory)
	}
	tr = NewRecoveryTimeTracker(-5)
	if tr.keep != DefaultRTOHistory {
		t.Errorf("keep = %d, want default %d for negative input", tr.keep, DefaultRTOHistory)
	}
}

func TestRecoveryTimeTracker_LastRecoverySeconds_EmptyHistory(t *testing.T) {
	tr := NewRecoveryTimeTracker(0)
	if _, ok := tr.LastRecoverySeconds(); ok {
		t.Error("LastRecoverySeconds() should report ok=false with no recorded recoveries")
	}
}
