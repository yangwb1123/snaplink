package dr

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDRReadiness_Evaluate_NilReplicator(t *testing.T) {
	dr := NewDRReadiness(nil, nil, time.Hour, 0)
	ready, lag, reason := dr.Evaluate()
	if ready || lag != 0 || !strings.Contains(reason, "not configured") {
		t.Errorf("Evaluate() = (%v, %v, %q), want not-ready/not-configured", ready, lag, reason)
	}
	if err := dr.ReadyCheck(context.Background()); err == nil {
		t.Error("ReadyCheck() should error when no replicator is wired")
	}
}

func TestDRReadiness_Evaluate_NoSuccessfulReplicationYet(t *testing.T) {
	r, err := NewSnapshotReplicator(fixedExport("snap_x", nil), t.TempDir(), 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	rdy := NewDRReadiness(r, nil, time.Hour, 0)
	ready, _, reason := rdy.Evaluate()
	if ready || !strings.Contains(reason, "no successful replication") {
		t.Errorf("Evaluate() = (%v, %q), want not-ready before any replication", ready, reason)
	}
}

// withLastSuccess builds a replicator whose lastSuccess is exactly age ago,
// bypassing a real replication cycle — the readiness math under test only
// depends on that timestamp.
func withLastSuccess(t *testing.T, age time.Duration) *SnapshotReplicator {
	t.Helper()
	r, err := NewSnapshotReplicator(fixedExport("snap_x", nil), t.TempDir(), 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	r.lastSuccess = time.Now().Add(-age)
	return r
}

func TestDRReadiness_Evaluate_WithinRPOTarget(t *testing.T) {
	rdy := NewDRReadiness(withLastSuccess(t, 10*time.Minute), nil, time.Hour, 0)
	ready, lag, reason := rdy.Evaluate()
	if !ready || reason != "" {
		t.Errorf("Evaluate() = (%v, %q), want ready within RPO target", ready, reason)
	}
	if lag < 590 || lag > 610 {
		t.Errorf("lag = %v, want ~600s", lag)
	}
	if err := rdy.ReadyCheck(context.Background()); err != nil {
		t.Errorf("ReadyCheck() = %v, want nil", err)
	}
}

func TestDRReadiness_Evaluate_ExceedsRPOTarget(t *testing.T) {
	rdy := NewDRReadiness(withLastSuccess(t, 2*time.Hour), nil, time.Hour, 0)
	ready, lag, reason := rdy.Evaluate()
	if ready || !strings.Contains(reason, "RPO target") {
		t.Errorf("Evaluate() = (%v, %q), want not-ready: lag %v exceeds target", ready, reason, lag)
	}
	if err := rdy.ReadyCheck(context.Background()); err == nil {
		t.Error("ReadyCheck() should error once the RPO target is exceeded")
	}
}

func TestDRReadiness_Evaluate_NoRPOTargetConfigured(t *testing.T) {
	// RPOTarget <= 0 means the operator set no commitment: any successful
	// replication, however old, counts as ready.
	rdy := NewDRReadiness(withLastSuccess(t, 100*time.Hour), nil, 0, 0)
	ready, _, reason := rdy.Evaluate()
	if !ready || reason != "" {
		t.Errorf("Evaluate() = (%v, %q), want ready with no RPO target set", ready, reason)
	}
}

func TestDRReadiness_Status_IncludesHistoryAndRetention(t *testing.T) {
	dir := t.TempDir()
	r, err := NewSnapshotReplicator(fixedExport("snap_2026-01-01T00-00-00Z_AAAAAA", []byte("payload")), dir, 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	if err := r.ReplicateOnce(context.Background()); err != nil {
		t.Fatalf("ReplicateOnce: %v", err)
	}

	tr := NewRecoveryTimeTracker(0)
	tr.now = stepClock(time.Now(), 42*time.Second)
	tr.Start("drill").Stop(nil)

	rdy := NewDRReadiness(r, tr, time.Hour, 30*time.Minute)
	st := rdy.Status(context.Background())

	if !st.Ready {
		t.Errorf("Status().Ready = false, want true: %+v", st)
	}
	if st.RPOTargetSeconds != 3600 {
		t.Errorf("RPOTargetSeconds = %v, want 3600", st.RPOTargetSeconds)
	}
	if st.RTOTargetSeconds != 1800 {
		t.Errorf("RTOTargetSeconds = %v, want 1800", st.RTOTargetSeconds)
	}
	if st.LastReplicationAt == nil {
		t.Error("LastReplicationAt should be set after a successful replication")
	}
	if len(st.RTOHistory) != 1 || st.RTOHistory[0].DurationSeconds != 42 {
		t.Errorf("RTOHistory = %+v, want one 42s record", st.RTOHistory)
	}
	if len(st.Retention) != 1 || st.Retention[0].Name != "snap_2026-01-01T00-00-00Z_AAAAAA.snap" {
		t.Errorf("Retention = %+v, want the one replicated file", st.Retention)
	}
}

func TestDRReadiness_Status_NilTrackerOmitsHistory(t *testing.T) {
	rdy := NewDRReadiness(withLastSuccess(t, time.Minute), nil, 0, 0)
	st := rdy.Status(context.Background())
	if st.RTOHistory != nil {
		t.Errorf("RTOHistory = %+v, want nil with no tracker wired", st.RTOHistory)
	}
}
