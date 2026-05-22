package detectors_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/defaultimpl/detectors"
)

func newBruteForce(t *testing.T, opts ...detectors.BruteForceShadowOption) (*detectors.BruteForceShadowDetector, anomaly.IPFailureCounter) {
	t.Helper()
	c := defaultimpl.NewMemoryIPFailureCounter()
	d, err := detectors.NewBruteForceShadowDetector(c, []byte("salt"), opts...)
	if err != nil {
		t.Fatalf("NewBruteForceShadowDetector: %v", err)
	}
	return d, c
}

func TestBruteForceShadow_FirstFailureNoSignal(t *testing.T) {
	d, _ := newBruteForce(t)
	got, err := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		RemoteIP:  "10.0.0.1",
		Outcome:   "failure",
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("first failure: %v", got)
	}
}

func TestBruteForceShadow_FailureLimitWarn(t *testing.T) {
	d, _ := newBruteForce(t,
		detectors.WithBruteForceShadowFailureLimit(5),
		detectors.WithBruteForceShadowDistinctSubjectLimit(0), // disable distinct
	)
	ctx := context.Background()
	now := time.Now()
	// 6 failures from one IP, same subject — exceeds failureLimit=5.
	for i := range 5 {
		_, _ = d.Inspect(ctx, &anomaly.LoginEvent{
			SubjectID: "alice",
			RemoteIP:  "10.0.0.1",
			Outcome:   "failure",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}
	got, _ := d.Inspect(ctx, &anomaly.LoginEvent{
		SubjectID: "alice",
		RemoteIP:  "10.0.0.1",
		Outcome:   "failure",
		Timestamp: now.Add(6 * time.Second),
	})
	if len(got) != 1 {
		t.Fatalf("6th failure should flag: %v", got)
	}
	if got[0].Severity != anomaly.SeverityWarn {
		t.Errorf("severity = %q, want warn", got[0].Severity)
	}
}

func TestBruteForceShadow_DistinctSubjectsCritical(t *testing.T) {
	d, _ := newBruteForce(t,
		detectors.WithBruteForceShadowFailureLimit(0), // disable total
		detectors.WithBruteForceShadowDistinctSubjectLimit(3),
	)
	ctx := context.Background()
	now := time.Now()
	// 4 failures from one IP across 4 distinct subjects.
	for i, name := range []string{"alice", "bob", "carol", "dave"} {
		_, _ = d.Inspect(ctx, &anomaly.LoginEvent{
			SubjectID: name,
			RemoteIP:  "10.0.0.1",
			Outcome:   "failure",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}
	// 5th failure (5 distinct now) — crosses threshold of 3.
	got, _ := d.Inspect(ctx, &anomaly.LoginEvent{
		SubjectID: "eve",
		RemoteIP:  "10.0.0.1",
		Outcome:   "failure",
		Timestamp: now.Add(5 * time.Second),
	})
	if len(got) != 1 {
		t.Fatalf("distinct=5 > limit=3: %v", got)
	}
	if got[0].Severity != anomaly.SeverityCritical {
		t.Errorf("severity = %q, want critical", got[0].Severity)
	}
}

func TestBruteForceShadow_SuccessFromSuspiciousIPFlags(t *testing.T) {
	// Attacker found valid creds after spraying: success from an
	// IP that's been hammering should ALSO surface (the counter
	// keeps the failure history; success just doesn't add to it).
	d, _ := newBruteForce(t,
		detectors.WithBruteForceShadowFailureLimit(5),
	)
	ctx := context.Background()
	now := time.Now()
	for i := range 10 {
		_, _ = d.Inspect(ctx, &anomaly.LoginEvent{
			SubjectID: "victim",
			RemoteIP:  "10.0.0.1",
			Outcome:   "failure",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}
	// Next event is a SUCCESS from the same IP.
	got, _ := d.Inspect(ctx, &anomaly.LoginEvent{
		SubjectID: "victim",
		RemoteIP:  "10.0.0.1",
		Outcome:   "success",
		Timestamp: now.Add(11 * time.Second),
	})
	if len(got) == 0 {
		t.Error("success from brute-forced IP should still flag")
	}
}

func TestBruteForceShadow_SuccessDoesntIncrement(t *testing.T) {
	// Successes don't add to the counter — only the existing
	// failure count matters when a success crosses the threshold.
	d, _ := newBruteForce(t,
		detectors.WithBruteForceShadowFailureLimit(5),
		detectors.WithBruteForceShadowDistinctSubjectLimit(0),
	)
	ctx := context.Background()
	now := time.Now()
	for range 100 {
		_, _ = d.Inspect(ctx, &anomaly.LoginEvent{
			SubjectID: "alice",
			RemoteIP:  "10.0.0.1",
			Outcome:   "success", // every event is success
			Timestamp: now,
		})
	}
	// Now a failure — should be only the 1st failure recorded.
	got, _ := d.Inspect(ctx, &anomaly.LoginEvent{
		SubjectID: "alice",
		RemoteIP:  "10.0.0.1",
		Outcome:   "failure",
		Timestamp: now.Add(1 * time.Second),
	})
	if len(got) != 0 {
		t.Errorf("100 successes shouldn't bump failure count: %v", got)
	}
}

func TestBruteForceShadow_OutOfWindowExcluded(t *testing.T) {
	d, _ := newBruteForce(t,
		detectors.WithBruteForceShadowWindow(10*time.Minute),
		detectors.WithBruteForceShadowFailureLimit(5),
	)
	ctx := context.Background()
	now := time.Now()
	// 10 failures, but 2 hours ago — outside 10-minute window.
	for i := range 10 {
		_, _ = d.Inspect(ctx, &anomaly.LoginEvent{
			SubjectID: "alice",
			RemoteIP:  "10.0.0.1",
			Outcome:   "failure",
			Timestamp: now.Add(-2*time.Hour - time.Duration(i)*time.Second),
		})
	}
	got, _ := d.Inspect(ctx, &anomaly.LoginEvent{
		SubjectID: "alice",
		RemoteIP:  "10.0.0.1",
		Outcome:   "failure",
		Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("out-of-window failures shouldn't count: %v", got)
	}
}

func TestBruteForceShadow_EmptyIPSkips(t *testing.T) {
	d, _ := newBruteForce(t)
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		RemoteIP:  "", // direct admin call or test setup
		Outcome:   "failure",
		Timestamp: time.Now(),
	})
	if got != nil {
		t.Errorf("empty IP: %v", got)
	}
}

func TestBruteForceShadow_NilCounterErrors(t *testing.T) {
	_, err := detectors.NewBruteForceShadowDetector(nil, []byte("salt"))
	if err == nil {
		t.Error("nil counter should error")
	}
}

func TestBruteForceShadow_NameStableWireString(t *testing.T) {
	d, _ := newBruteForce(t)
	if got := d.Name(); got != "brute_force_shadow" {
		t.Errorf("Name = %q, want brute_force_shadow", got)
	}
}

func TestBruteForceShadow_BothThresholdsFireTwoAnomalies(t *testing.T) {
	d, _ := newBruteForce(t,
		detectors.WithBruteForceShadowFailureLimit(5),
		detectors.WithBruteForceShadowDistinctSubjectLimit(3),
	)
	ctx := context.Background()
	now := time.Now()
	// 10 failures across 5 subjects — crosses both thresholds.
	subjects := []string{"a", "b", "c", "d", "e"}
	for i := range 10 {
		_, _ = d.Inspect(ctx, &anomaly.LoginEvent{
			SubjectID: subjects[i%len(subjects)],
			RemoteIP:  "10.0.0.1",
			Outcome:   "failure",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}
	got, _ := d.Inspect(ctx, &anomaly.LoginEvent{
		SubjectID: "f",
		RemoteIP:  "10.0.0.1",
		Outcome:   "failure",
		Timestamp: now.Add(11 * time.Second),
	})
	if len(got) != 2 {
		t.Fatalf("both thresholds: want 2 anomalies, got %d", len(got))
	}
	severities := map[anomaly.Severity]bool{}
	for _, a := range got {
		severities[a.Severity] = true
	}
	if !severities[anomaly.SeverityWarn] || !severities[anomaly.SeverityCritical] {
		t.Errorf("should have both warn + critical: %v", severities)
	}
}
