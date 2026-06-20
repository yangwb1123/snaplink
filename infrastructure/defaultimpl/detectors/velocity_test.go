package detectors_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/detectors"
)

func newVelocity(t *testing.T, opts ...detectors.VelocityOption) (*detectors.VelocityDetector, anomaly.RecentLoginStore) {
	t.Helper()
	store := defaultimpl.NewMemoryRecentLoginStore()
	d, err := detectors.NewVelocityDetector(store, opts...)
	if err != nil {
		t.Fatalf("NewVelocityDetector: %v", err)
	}
	return d, store
}

func seedRecent(t *testing.T, store anomaly.RecentLoginStore, subject string, count int, spread time.Duration, end time.Time) {
	t.Helper()
	ctx := context.Background()
	step := spread / time.Duration(count)
	for i := range count {
		ts := end.Add(-time.Duration(i) * step)
		if err := store.Append(ctx, &anomaly.LoginEntry{
			SubjectID: subject,
			Outcome:   "failure",
			Timestamp: ts,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func TestVelocity_NoHistoryNoSignal(t *testing.T) {
	d, _ := newVelocity(t)
	got, err := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty history should produce no anomaly: %v", got)
	}
}

func TestVelocity_BelowHourlyThresholdNoSignal(t *testing.T) {
	d, store := newVelocity(t, detectors.WithVelocityHourlyLimit(10))
	now := time.Now()
	// 5 attempts in past hour — under threshold.
	seedRecent(t, store, "alice", 5, 30*time.Minute, now.Add(-5*time.Second))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice", Timestamp: now,
	})
	// 5 seeded + 1 current = 6 ≤ 10, no anomaly.
	if len(got) != 0 {
		t.Errorf("6 attempts ≤ 10 limit: %v", got)
	}
}

func TestVelocity_HourlyThresholdWarn(t *testing.T) {
	d, store := newVelocity(t, detectors.WithVelocityHourlyLimit(10))
	now := time.Now()
	seedRecent(t, store, "alice", 15, 30*time.Minute, now.Add(-5*time.Second))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice", Timestamp: now,
	})
	if len(got) != 1 {
		t.Fatalf("hourly threshold: want 1 anomaly, got %d", len(got))
	}
	a := got[0]
	if a.Severity != anomaly.SeverityWarn {
		t.Errorf("hourly severity = %q, want warn", a.Severity)
	}
	if a.Evidence["window"] != "1h" {
		t.Errorf("evidence window: %v", a.Evidence)
	}
}

func TestVelocity_DailyThresholdCritical(t *testing.T) {
	d, store := newVelocity(t,
		detectors.WithVelocityHourlyLimit(0), // disable hourly to isolate daily
		detectors.WithVelocityDailyLimit(50),
	)
	now := time.Now()
	// Spread 60 attempts across 12h so they're outside the 1h
	// window — only daily fires.
	seedRecent(t, store, "alice", 60, 12*time.Hour, now.Add(-2*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice", Timestamp: now,
	})
	if len(got) != 1 {
		t.Fatalf("daily only: want 1 anomaly, got %d", len(got))
	}
	if got[0].Severity != anomaly.SeverityCritical {
		t.Errorf("daily severity = %q, want critical", got[0].Severity)
	}
}

func TestVelocity_BothThresholdsFireTwoAnomalies(t *testing.T) {
	d, store := newVelocity(t,
		detectors.WithVelocityHourlyLimit(10),
		detectors.WithVelocityDailyLimit(50),
	)
	now := time.Now()
	// 60 attempts in past 30min → exceeds both 10/hour AND 50/day.
	seedRecent(t, store, "alice", 60, 30*time.Minute, now.Add(-5*time.Second))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice", Timestamp: now,
	})
	if len(got) != 2 {
		t.Fatalf("both thresholds: want 2 anomalies, got %d", len(got))
	}
	severities := map[anomaly.Severity]bool{}
	for _, a := range got {
		severities[a.Severity] = true
	}
	if !severities[anomaly.SeverityWarn] || !severities[anomaly.SeverityCritical] {
		t.Errorf("should have both warn (hourly) + critical (daily): %v", severities)
	}
}

func TestVelocity_ZeroLimitDisablesCheck(t *testing.T) {
	d, store := newVelocity(t,
		detectors.WithVelocityHourlyLimit(0),
		detectors.WithVelocityDailyLimit(0),
	)
	now := time.Now()
	seedRecent(t, store, "alice", 500, 12*time.Hour, now.Add(-5*time.Second))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice", Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("both zero limits = disabled: %v", got)
	}
}

func TestVelocity_OutOfWindowAttemptsExcluded(t *testing.T) {
	// Seed many entries 25+ hours old — outside daily window.
	d, store := newVelocity(t, detectors.WithVelocityHourlyLimit(5))
	now := time.Now()
	for i := range 50 {
		_ = store.Append(context.Background(), &anomaly.LoginEntry{
			SubjectID: "alice",
			Timestamp: now.Add(-30*time.Hour - time.Duration(i)*time.Minute),
		})
	}
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice", Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("out-of-window entries shouldn't count: %v", got)
	}
}

func TestVelocity_EmptySubjectNoSignal(t *testing.T) {
	d, _ := newVelocity(t)
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{Outcome: "failure"})
	if got != nil {
		t.Errorf("empty subject: %v", got)
	}
}

func TestVelocity_NilEventNoSignal(t *testing.T) {
	d, _ := newVelocity(t)
	got, _ := d.Inspect(context.Background(), nil)
	if got != nil {
		t.Errorf("nil event: %v", got)
	}
}

func TestVelocity_NilStoreErrors(t *testing.T) {
	_, err := detectors.NewVelocityDetector(nil)
	if err == nil {
		t.Error("nil store should error")
	}
}

func TestVelocity_NameIsStableWireString(t *testing.T) {
	d, _ := newVelocity(t)
	if got := d.Name(); got != detectors.DetectorTypeVelocity {
		t.Errorf("Name = %q, want %q", got, detectors.DetectorTypeVelocity)
	}
	if detectors.DetectorTypeVelocity != "velocity_burst" {
		t.Errorf("wire string drifted: %q", detectors.DetectorTypeVelocity)
	}
}

func TestVelocity_DoesNotWriteToStore(t *testing.T) {
	// Velocity is read-only — impossible-travel owns the writes.
	d, store := newVelocity(t)
	now := time.Now()
	_, _ = d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice", Timestamp: now,
	})
	got, _ := store.Recent(context.Background(), "alice", time.Time{}, 0)
	if len(got) != 0 {
		t.Errorf("velocity wrote to store: %d entries", len(got))
	}
}

func TestVelocity_ScoreCappedAt100(t *testing.T) {
	// Score is in the anomaly Score field 0..100.
	d, store := newVelocity(t, detectors.WithVelocityHourlyLimit(2))
	now := time.Now()
	seedRecent(t, store, "alice", 50, 30*time.Minute, now.Add(-1*time.Second))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice", Timestamp: now,
	})
	if len(got) == 0 {
		t.Fatal("expected anomaly")
	}
	for _, a := range got {
		if a.Score < 0 || a.Score > 100 {
			t.Errorf("score out of range: %d", a.Score)
		}
	}
}
