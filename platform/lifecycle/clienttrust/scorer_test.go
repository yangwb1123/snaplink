package clienttrust_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/lifecycle/clienttrust"
	"github.com/yangwb1123/snaplink/shared/trust"
)

func approxEqual(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestClientTrustScorer_NoSignal(t *testing.T) {
	t.Parallel()
	var scorer clienttrust.ClientTrustScorer // zero value: Activity nil
	got, err := scorer.Score(context.Background(), trust.TrustSignals{ClientID: "c1"})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if !approxEqual(got.Value, clienttrust.ColdStartScore) {
		t.Errorf("Value = %v, want ColdStartScore (%v)", got.Value, clienttrust.ColdStartScore)
	}
	if len(got.Reasons) == 0 || got.Reasons[0] != "client_activity:no_signal" {
		t.Errorf("Reasons = %v, want [client_activity:no_signal]", got.Reasons)
	}
}

func TestClientTrustScorer_ColdStartNoHistory(t *testing.T) {
	t.Parallel()
	scorer := &clienttrust.ClientTrustScorer{Activity: clienttrust.NewMemoryClientActivityStore()}
	got, err := scorer.Score(context.Background(), trust.TrustSignals{ClientID: "new-client", Time: time.Now()})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if !approxEqual(got.Value, clienttrust.ColdStartScore) {
		t.Errorf("Value = %v, want ColdStartScore (a never-scored client must never read as 0.0)", got.Value)
	}
	if got.Reasons[0] != "client_activity:cold_start" {
		t.Errorf("Reasons = %v, want [client_activity:cold_start]", got.Reasons)
	}
}

func TestClientTrustScorer_HighFailureRate(t *testing.T) {
	t.Parallel()
	store := clienttrust.NewMemoryClientActivityStore()
	now := time.Now()
	for i := 0; i < 6; i++ {
		mustRecord(t, store, "c1", clienttrust.ClientActivityAuthFailure, now.Add(-time.Minute))
	}
	for i := 0; i < 2; i++ {
		mustRecord(t, store, "c1", clienttrust.ClientActivityAuthSuccess, now.Add(-time.Minute))
	}
	scorer := &clienttrust.ClientTrustScorer{Activity: store}
	got, err := scorer.Score(context.Background(), trust.TrustSignals{ClientID: "c1", Time: now})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	// 6/8 = 75% failure rate >= the 50% default threshold: penalized 0.4 -> score 0.6.
	if !approxEqual(got.Value, 0.6) {
		t.Errorf("Value = %v, want 0.6 (1 - failureRatePenalty)", got.Value)
	}
	if !containsReason(got.Reasons, "client_activity:high_failure_rate") {
		t.Errorf("Reasons = %v, want to contain high_failure_rate", got.Reasons)
	}
}

func TestClientTrustScorer_FrequentRotationAnomaly(t *testing.T) {
	t.Parallel()
	store := clienttrust.NewMemoryClientActivityStore()
	now := time.Now()
	for i := 0; i < clienttrust.DefaultRotationFrequencyThreshold; i++ {
		mustRecord(t, store, "c1", clienttrust.ClientActivitySecretRotation, now.Add(-time.Minute))
	}
	scorer := &clienttrust.ClientTrustScorer{Activity: store}
	got, err := scorer.Score(context.Background(), trust.TrustSignals{ClientID: "c1", Time: now})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if !approxEqual(got.Value, 0.7) {
		t.Errorf("Value = %v, want 0.7 (1 - rotationFrequencyPenalty)", got.Value)
	}
	if !containsReason(got.Reasons, "client_activity:frequent_rotation") {
		t.Errorf("Reasons = %v, want to contain frequent_rotation", got.Reasons)
	}
}

func TestClientTrustScorer_ScopeAnomaly(t *testing.T) {
	t.Parallel()
	store := clienttrust.NewMemoryClientActivityStore()
	now := time.Now()
	mustRecord(t, store, "c1", clienttrust.ClientActivityScopeAnomaly, now.Add(-time.Minute))
	scorer := &clienttrust.ClientTrustScorer{Activity: store}
	got, err := scorer.Score(context.Background(), trust.TrustSignals{ClientID: "c1", Time: now})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if !approxEqual(got.Value, 0.7) {
		t.Errorf("Value = %v, want 0.7 (1 - scopeAnomalyPenalty)", got.Value)
	}
	if !containsReason(got.Reasons, "client_activity:scope_anomaly") {
		t.Errorf("Reasons = %v, want to contain scope_anomaly", got.Reasons)
	}
}

func TestClientTrustScorer_CleanHistoryScoresFull(t *testing.T) {
	t.Parallel()
	store := clienttrust.NewMemoryClientActivityStore()
	now := time.Now()
	for i := 0; i < 5; i++ {
		mustRecord(t, store, "c1", clienttrust.ClientActivityAuthSuccess, now.Add(-time.Minute))
	}
	scorer := &clienttrust.ClientTrustScorer{Activity: store}
	got, err := scorer.Score(context.Background(), trust.TrustSignals{ClientID: "c1", Time: now})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if !approxEqual(got.Value, 1.0) {
		t.Errorf("Value = %v, want 1.0 (clean record)", got.Value)
	}
	if !containsReason(got.Reasons, "client_activity:clean") {
		t.Errorf("Reasons = %v, want [client_activity:clean]", got.Reasons)
	}
}

// TestClientTrustScorer_DecayRecoversOverTime proves the rule-based penalty
// reuses shared/trust's decay curve: scoring immediately after a rotation
// burst yields the full raw penalty, but re-scoring long afterward (with no
// NEW negative activity) recovers most of the way back toward a clean score.
func TestClientTrustScorer_DecayRecoversOverTime(t *testing.T) {
	t.Parallel()
	store := clienttrust.NewMemoryClientActivityStore()
	base := time.Now()
	for i := 0; i < clienttrust.DefaultRotationFrequencyThreshold; i++ {
		mustRecord(t, store, "c1", clienttrust.ClientActivitySecretRotation, base)
	}
	scorer := &clienttrust.ClientTrustScorer{
		Activity: store,
		Decay:    trust.DecayConfig{Interval: time.Hour, Factor: 0.5},
	}

	immediate, err := scorer.Score(context.Background(), trust.TrustSignals{ClientID: "c1", Time: base})
	if err != nil {
		t.Fatalf("Score (immediate): %v", err)
	}
	if !approxEqual(immediate.Value, 0.7) {
		t.Fatalf("immediate Value = %v, want 0.7 (no elapsed time yet, undecayed penalty)", immediate.Value)
	}

	later, err := scorer.Score(context.Background(), trust.TrustSignals{ClientID: "c1", Time: base.Add(10 * time.Hour)})
	if err != nil {
		t.Fatalf("Score (later): %v", err)
	}
	if later.Value <= immediate.Value {
		t.Fatalf("later Value = %v must have recovered above the immediate score %v", later.Value, immediate.Value)
	}
	if later.Value < 0.99 {
		t.Errorf("later Value = %v, want >= 0.99 (10 half-lives should nearly fully recover)", later.Value)
	}
}

func containsReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
