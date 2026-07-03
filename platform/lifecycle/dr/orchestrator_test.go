package dr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// replicatorWithReplica builds a real SnapshotReplicator over t.TempDir and
// runs one ReplicateOnce so LatestReplica has something to return. Returns the
// replicator plus the replica's on-disk file name and bytes.
func replicatorWithReplica(t *testing.T) (*SnapshotReplicator, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	payload := []byte(`{"envelope_version":"1","body":"c2VhbGVk"}`)
	r, err := NewSnapshotReplicator(fixedExport("snap_2026-07-03T00-00-00Z_AAAAAA", payload), dir, 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	if err := r.ReplicateOnce(context.Background()); err != nil {
		t.Fatalf("ReplicateOnce: %v", err)
	}
	name, data, err := r.LatestReplica()
	if err != nil {
		t.Fatalf("LatestReplica: %v", err)
	}
	return r, name, data
}

// verifierFor registers the given replica so the memory verifier accepts
// exactly those bytes.
func verifierFor(name string, data []byte) *MemoryReplicaVerifier {
	v := NewMemoryReplicaVerifier()
	v.Register(name, data)
	return v
}

func TestNewRecoveryOrchestrator_RequiresSeams(t *testing.T) {
	r, _, _ := replicatorWithReplica(t)
	if _, err := NewRecoveryOrchestrator(OrchestratorConfig{Verifier: NewMemoryReplicaVerifier()}); err == nil {
		t.Error("expected error for missing replicator")
	}
	if _, err := NewRecoveryOrchestrator(OrchestratorConfig{Replicator: r}); err == nil {
		t.Error("expected error for missing verifier")
	}
}

func TestRecoveryOrchestrator_HappyPath(t *testing.T) {
	r, name, data := replicatorWithReplica(t)
	promoter := &MemoryReplicaPromoter{}
	restorer := &MemoryStateRestorer{}
	o, err := NewRecoveryOrchestrator(OrchestratorConfig{
		Replicator: r,
		Verifier:   verifierFor(name, data),
		Promoter:   promoter,
		Restorer:   restorer,
		Readiness:  NewDRReadiness(r, NewRecoveryTimeTracker(0), 0, time.Hour),
		Tracker:    NewRecoveryTimeTracker(0),
		RTOTarget:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewRecoveryOrchestrator: %v", err)
	}
	rep := o.Run(context.Background())
	if !rep.Succeeded {
		t.Fatalf("expected success, got %+v", rep)
	}
	if len(rep.Steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(rep.Steps))
	}
	for _, s := range rep.Steps {
		if s.Outcome != StepSuccess {
			t.Errorf("step %s outcome = %q, want success", s.Name, s.Outcome)
		}
	}
	if promoter.Calls() != 1 {
		t.Errorf("promoter calls = %d, want 1", promoter.Calls())
	}
	// The restore step must receive the SAME bytes the integrity step verified.
	gotName, gotLen, calls := restorer.Last()
	if gotName != name || gotLen != len(data) || calls != 1 {
		t.Errorf("restorer got (%q,%d,%d), want (%q,%d,1)", gotName, gotLen, calls, name, len(data))
	}
	if !rep.RTOWithinTarget {
		t.Error("a fast successful drill should be within the 1h RTO target")
	}
	if o.LastReport() != rep {
		t.Error("LastReport should return the most recent report")
	}
}

func TestRecoveryOrchestrator_IntegrityFailureAborts(t *testing.T) {
	r, name, data := replicatorWithReplica(t)
	// Corrupt the replica on disk AFTER registering the original digest so the
	// verifier detects the tamper — exactly the "a corrupted DR is worse than a
	// missing one" gate. Overwrite in place so LatestReplica reads the garbage.
	if err := os.WriteFile(filepath.Join(r.TargetDir, name), []byte("corrupted-bytes"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	promoter := &MemoryReplicaPromoter{}
	restorer := &MemoryStateRestorer{}
	o, _ := NewRecoveryOrchestrator(OrchestratorConfig{
		Replicator: r,
		Verifier:   verifierFor(name, data), // digest of the ORIGINAL bytes
		Promoter:   promoter,
		Restorer:   restorer,
	})
	rep := o.Run(context.Background())
	if rep.Succeeded {
		t.Fatal("expected abort on integrity failure")
	}
	if rep.AbortedAtStep != StepVerifyIntegrity {
		t.Errorf("aborted at %q, want %q", rep.AbortedAtStep, StepVerifyIntegrity)
	}
	// Nothing downstream of the failed integrity check may run.
	if promoter.Calls() != 0 {
		t.Errorf("promoter ran %d times after integrity failure; must be 0", promoter.Calls())
	}
	if _, _, calls := restorer.Last(); calls != 0 {
		t.Errorf("restorer ran %d times after integrity failure; must be 0", calls)
	}
	// Later steps are recorded as skipped so the report shows the full plan.
	assertOutcomes(t, rep, StepFailure, StepSkipped, StepSkipped, StepSkipped)
	if rep.RTOWithinTarget {
		t.Error("an aborted drill must not report within-target")
	}
}

func TestRecoveryOrchestrator_PromoteFailureAborts(t *testing.T) {
	r, name, data := replicatorWithReplica(t)
	restorer := &MemoryStateRestorer{}
	o, _ := NewRecoveryOrchestrator(OrchestratorConfig{
		Replicator: r,
		Verifier:   verifierFor(name, data),
		Promoter:   &MemoryReplicaPromoter{FailWith: errors.New("promotion refused")},
		Restorer:   restorer,
	})
	rep := o.Run(context.Background())
	if rep.Succeeded || rep.AbortedAtStep != StepPromoteReplica {
		t.Fatalf("expected abort at promote, got succeeded=%v aborted=%q", rep.Succeeded, rep.AbortedAtStep)
	}
	if _, _, calls := restorer.Last(); calls != 0 {
		t.Error("restore must not run after a failed promotion")
	}
	assertOutcomes(t, rep, StepSuccess, StepFailure, StepSkipped, StepSkipped)
}

func TestRecoveryOrchestrator_RestoreFailureAborts(t *testing.T) {
	r, name, data := replicatorWithReplica(t)
	o, _ := NewRecoveryOrchestrator(OrchestratorConfig{
		Replicator: r,
		Verifier:   verifierFor(name, data),
		Promoter:   &MemoryReplicaPromoter{},
		Restorer:   &MemoryStateRestorer{FailWith: errors.New("restore blew up")},
		Readiness:  NewDRReadiness(r, nil, 0, 0),
	})
	rep := o.Run(context.Background())
	if rep.Succeeded || rep.AbortedAtStep != StepRestoreState {
		t.Fatalf("expected abort at restore, got succeeded=%v aborted=%q", rep.Succeeded, rep.AbortedAtStep)
	}
	assertOutcomes(t, rep, StepSuccess, StepSuccess, StepFailure, StepSkipped)
}

func TestRecoveryOrchestrator_OptionalSeamsSkip(t *testing.T) {
	r, name, data := replicatorWithReplica(t)
	// Only the required seams — promote/restore/readiness left nil.
	o, _ := NewRecoveryOrchestrator(OrchestratorConfig{
		Replicator: r,
		Verifier:   verifierFor(name, data),
	})
	rep := o.Run(context.Background())
	if !rep.Succeeded {
		t.Fatalf("skipped optional steps must not fail the run: %+v", rep)
	}
	assertOutcomes(t, rep, StepSuccess, StepSkipped, StepSkipped, StepSkipped)
}

func TestRecoveryOrchestrator_RTOOverTarget(t *testing.T) {
	r, name, data := replicatorWithReplica(t)
	o, _ := NewRecoveryOrchestrator(OrchestratorConfig{
		Replicator: r,
		Verifier:   verifierFor(name, data),
		RTOTarget:  time.Nanosecond, // impossibly tight
	})
	// Drive a fake clock that advances 1s on every read so the measured RTO
	// clearly exceeds the 1ns target even on a successful run.
	var ticks int
	base := time.Unix(1_700_000_000, 0)
	o.now = func() time.Time {
		ticks++
		return base.Add(time.Duration(ticks) * time.Second)
	}
	rep := o.Run(context.Background())
	if !rep.Succeeded {
		t.Fatalf("run should succeed even while over the RTO target: %+v", rep)
	}
	if rep.MeasuredRTOSeconds <= 0 {
		t.Errorf("measured RTO = %v, want > 0", rep.MeasuredRTOSeconds)
	}
	if rep.RTOWithinTarget {
		t.Error("a run far over the RTO target must report within_target=false")
	}
}

func TestRecoveryOrchestrator_NoReplicaAborts(t *testing.T) {
	dir := t.TempDir()
	r, err := NewSnapshotReplicator(fixedExport("snap_x", []byte("x")), dir, 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	// No ReplicateOnce — the target dir is empty.
	o, _ := NewRecoveryOrchestrator(OrchestratorConfig{Replicator: r, Verifier: NewMemoryReplicaVerifier()})
	rep := o.Run(context.Background())
	if rep.Succeeded || rep.AbortedAtStep != StepVerifyIntegrity {
		t.Fatalf("empty target dir should abort at integrity, got %+v", rep)
	}
	if rep.Steps[0].Error == "" {
		t.Error("integrity step should carry the ErrNoReplica error text")
	}
}

func TestDRReadiness_StatusSurfacesLastDrill(t *testing.T) {
	r, name, data := replicatorWithReplica(t)
	o, _ := NewRecoveryOrchestrator(OrchestratorConfig{Replicator: r, Verifier: verifierFor(name, data)})
	readiness := NewDRReadiness(r, NewRecoveryTimeTracker(0), 0, 0)
	readiness.Orchestrator = o

	// Before any drill: no report card surfaced (byte-identical to today).
	if st := readiness.Status(context.Background()); st.LastDrill != nil {
		t.Error("LastDrill should be nil before any drill runs")
	}
	rep := o.Run(context.Background())
	st := readiness.Status(context.Background())
	if st.LastDrill == nil || st.LastDrill != rep {
		t.Fatal("Status should surface the orchestrator's last report card after a drill")
	}
}

// assertOutcomes checks the report's per-step outcomes in order.
func assertOutcomes(t *testing.T, rep *RecoveryReport, want ...string) {
	t.Helper()
	if len(rep.Steps) != len(want) {
		t.Fatalf("got %d steps, want %d (%+v)", len(rep.Steps), len(want), rep.Steps)
	}
	for i, w := range want {
		if rep.Steps[i].Outcome != w {
			t.Errorf("step[%d] (%s) outcome = %q, want %q", i, rep.Steps[i].Name, rep.Steps[i].Outcome, w)
		}
	}
}
