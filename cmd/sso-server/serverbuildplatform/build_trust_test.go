package serverbuildplatform

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/detectors"
	"github.com/snaplink/sso/shared/trust"
)

// build_trust_test.go proves ROADMAP 6g: the anomaly-store adapters land in
// the SAME hash space the real detectors write (no hand-rolled mocks — the
// writes go through the real BruteForceShadowDetector + Memory* stores), and
// BuildTrustScorer maps the trust.* config onto the reference scorers,
// failing loud on the silent-dead-config shapes (no weights, typo'd scorer,
// non-positive weight).

const (
	testAttackerIP = "203.0.113.7"
	testCleanIP    = "198.51.100.9"
)

// seedIPFailures drives n failure events for ip through the REAL
// brute-force-shadow detector so the counter rows carry the detector's own
// salted IP hash — the invariant the adapter must reproduce on read.
func seedIPFailures(t *testing.T, counter anomaly.IPFailureCounter, salt []byte, ip string, n int, at time.Time) {
	t.Helper()
	det, err := detectors.NewBruteForceShadowDetector(counter, salt)
	if err != nil {
		t.Fatalf("NewBruteForceShadowDetector: %v", err)
	}
	subjects := []string{"alice", "bob", "carol", "dave", "erin"}
	for i := 0; i < n; i++ {
		_, err := det.Inspect(context.Background(), &anomaly.LoginEvent{
			SubjectID: subjects[i%len(subjects)],
			Outcome:   "failure",
			RemoteIP:  ip,
			Timestamp: at.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("Inspect failure %d: %v", i, err)
		}
	}
}

func TestAnomalyIPFailureLookup_ReadsDetectorWrites(t *testing.T) {
	t.Parallel()
	salt := []byte("deployment-salt")
	counter := defaultimpl.NewMemoryIPFailureCounter()
	now := time.Now()
	seedIPFailures(t, counter, salt, testAttackerIP, 3, now)

	lookup := NewAnomalyIPFailureLookup(counter, salt)
	total, distinct, err := lookup.CountFailures(context.Background(), testAttackerIP, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("CountFailures: %v", err)
	}
	if total != 3 || distinct != 3 {
		t.Errorf("CountFailures = (%d, %d); want (3, 3) — adapter hash does not match the detector's write hash", total, distinct)
	}

	// A different IP and the anonymous (empty) IP both count nothing.
	if total, distinct, err = lookup.CountFailures(context.Background(), testCleanIP, now.Add(-time.Minute)); err != nil || total != 0 || distinct != 0 {
		t.Errorf("clean IP CountFailures = (%d, %d, %v); want (0, 0, nil)", total, distinct, err)
	}
	if total, distinct, err = lookup.CountFailures(context.Background(), "", now.Add(-time.Minute)); err != nil || total != 0 || distinct != 0 {
		t.Errorf("empty IP CountFailures = (%d, %d, %v); want (0, 0, nil)", total, distinct, err)
	}
}

func TestAnomalyIPFailureLookup_SaltMismatchCountsNothing(t *testing.T) {
	t.Parallel()
	counter := defaultimpl.NewMemoryIPFailureCounter()
	now := time.Now()
	seedIPFailures(t, counter, []byte("salt-a"), testAttackerIP, 3, now)

	lookup := NewAnomalyIPFailureLookup(counter, []byte("salt-b"))
	total, distinct, err := lookup.CountFailures(context.Background(), testAttackerIP, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("CountFailures: %v", err)
	}
	if total != 0 || distinct != 0 {
		t.Errorf("mismatched salt CountFailures = (%d, %d); want (0, 0)", total, distinct)
	}
}

func TestAnomalyLoginHistory_FiltersFailures(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryRecentLoginStore()
	base := time.Now().Add(-time.Hour)
	entries := []*anomaly.LoginEntry{
		{SubjectID: "alice", Outcome: "success", Timestamp: base},
		{SubjectID: "alice", Outcome: "failure", Timestamp: base.Add(time.Minute)},
		{SubjectID: "alice", Outcome: "success", Timestamp: base.Add(2 * time.Minute)},
		{SubjectID: "bob", Outcome: "success", Timestamp: base.Add(3 * time.Minute)},
	}
	for _, e := range entries {
		if err := store.Append(context.Background(), e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	hist, err := NewAnomalyLoginHistory(store).History(context.Background(), "alice", 10)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("History returned %d timestamps; want 2 (successes only, alice only)", len(hist))
	}
	for _, ts := range hist {
		if ts.Equal(base.Add(time.Minute)) {
			t.Error("History returned the failure timestamp; failures must be filtered")
		}
	}
}

func TestBuildTrustScorer_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	scorer, err := BuildTrustScorer(config.TrustConfig{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildTrustScorer: %v", err)
	}
	if scorer != nil {
		t.Error("disabled trust config built a scorer; want nil (byte-identical build)")
	}
}

func TestBuildTrustScorer_FailsLoud(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		weights map[string]float64
	}{
		{"no weights", nil},
		{"unknown scorer", map[string]float64{"geo_risk": 1, "ip_reputatoin": 1}},
		{"non-positive weight", map[string]float64{"behavior": 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.TrustConfig{Enabled: true, Weights: tc.weights}
			if _, err := BuildTrustScorer(cfg, nil, nil, nil); err == nil {
				t.Errorf("BuildTrustScorer(%s) = nil error; want loud boot failure", tc.name)
			}
		})
	}
}

// TestBuildTrustScorer_ThresholdsReachTheScorer proves the config knobs
// actually govern scoring: with failure_threshold 3 and three real detector-
// recorded failures, the anomaly-backed composite scores the attacker IP
// suspicious, while an unseen IP scores clean.
func TestBuildTrustScorer_ThresholdsReachTheScorer(t *testing.T) {
	t.Parallel()
	salt := []byte("deployment-salt")
	counter := defaultimpl.NewMemoryIPFailureCounter()
	now := time.Now()
	seedIPFailures(t, counter, salt, testAttackerIP, 3, now)

	cfg := config.TrustConfig{Enabled: true, Weights: map[string]float64{"ip_reputation": 1}}
	cfg.IPReputation.FailureThreshold = 3
	cfg.IPReputation.Window = time.Hour
	scorer, err := BuildTrustScorer(cfg, NewAnomalyIPFailureLookup(counter, salt), nil, nil)
	if err != nil {
		t.Fatalf("BuildTrustScorer: %v", err)
	}

	suspicious, err := scorer.Score(context.Background(), trust.TrustSignals{RemoteIP: testAttackerIP, Time: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Score(attacker): %v", err)
	}
	clean, err := scorer.Score(context.Background(), trust.TrustSignals{RemoteIP: testCleanIP, Time: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Score(clean): %v", err)
	}
	if suspicious.Value >= clean.Value {
		t.Errorf("attacker score %.2f >= clean score %.2f; failure threshold did not reach the scorer", suspicious.Value, clean.Value)
	}
	if !hasReason(suspicious.Reasons, "ip_reputation:high_failure_volume") {
		t.Errorf("attacker Reasons = %v; want ip_reputation:high_failure_volume", suspicious.Reasons)
	}
}

// TestBuildTrustScorer_AllScorersCompose proves a four-scorer composite built
// purely from config scores without error and stays in [0,1] with every
// scorer contributing a reason.
func TestBuildTrustScorer_AllScorersCompose(t *testing.T) {
	t.Parallel()
	cfg := config.TrustConfig{Enabled: true, Weights: map[string]float64{
		"geo_risk": 1, "ip_reputation": 1, "behavior": 1, "device_posture": 1,
	}}
	cfg.DevicePosture.DefaultScore = 0.3
	scorer, err := BuildTrustScorer(cfg,
		NewAnomalyIPFailureLookup(defaultimpl.NewMemoryIPFailureCounter(), nil),
		NewAnomalyLoginHistory(defaultimpl.NewMemoryRecentLoginStore()), nil)
	if err != nil {
		t.Fatalf("BuildTrustScorer: %v", err)
	}
	score, err := scorer.Score(context.Background(), trust.TrustSignals{
		RemoteIP: testCleanIP, UserID: "alice", Time: time.Now(),
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if score.Value < 0 || score.Value > 1 {
		t.Errorf("composite score %v outside [0,1]", score.Value)
	}
	for _, prefix := range []string{"geo_risk:", "ip_reputation:", "behavior:", "device_posture:"} {
		if !hasReasonPrefix(score.Reasons, prefix) {
			t.Errorf("Reasons %v missing contribution from %s", score.Reasons, prefix)
		}
	}
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

func hasReasonPrefix(reasons []string, prefix string) bool {
	for _, r := range reasons {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}
