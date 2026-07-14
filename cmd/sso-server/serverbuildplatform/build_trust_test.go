package serverbuildplatform

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/trust"
)

func TestBuildTrustScorer_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	scorer, err := BuildTrustScorer(config.TrustConfig{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildTrustScorer: %v", err)
	}
	if scorer != nil {
		t.Fatalf("disabled trust scoring must return nil; got %v", scorer)
	}
}

func TestBuildTrustScorer_EnabledEmptyWeightsFailsLoud(t *testing.T) {
	t.Parallel()
	_, err := BuildTrustScorer(config.TrustConfig{Enabled: true}, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error: trust.enabled=true with no weights configured")
	}
}

func TestBuildTrustScorer_UnknownScorerNameFailsLoud(t *testing.T) {
	t.Parallel()
	cfg := config.TrustConfig{
		Enabled: true,
		Weights: map[string]float64{"not_a_real_scorer": 1.0},
	}
	_, err := BuildTrustScorer(cfg, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error: unknown scorer name in trust.weights")
	}
}

func TestBuildTrustScorer_NonPositiveWeightFailsLoud(t *testing.T) {
	t.Parallel()
	for _, w := range []float64{0, -1} {
		cfg := config.TrustConfig{
			Enabled: true,
			Weights: map[string]float64{"geo_risk": w},
		}
		if _, err := BuildTrustScorer(cfg, nil, nil, nil, nil); err == nil {
			t.Fatalf("weight=%v: expected error: trust.weights entries must be > 0", w)
		}
	}
}

func TestBuildTrustScorer_EnabledValidWeightsBuildsComposite(t *testing.T) {
	t.Parallel()
	cfg := config.TrustConfig{
		Enabled: true,
		Weights: map[string]float64{
			"geo_risk":       1,
			"ip_reputation":  1,
			"behavior":       1,
			"device_posture": 1,
		},
	}
	scorer, err := BuildTrustScorer(cfg, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildTrustScorer: %v", err)
	}
	if scorer == nil {
		t.Fatal("enabled trust scoring with valid weights must return a non-nil composite")
	}
	// Every scorer must degrade to a cold-start / stub value with nil stores —
	// never an error — so Score itself must succeed end to end.
	got, err := scorer.Score(context.Background(), trustTestSignals())
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Value < 0 || got.Value > 1 {
		t.Errorf("composite score = %v; want in [0,1]", got.Value)
	}
}

// TestBuildTrustScorer_MetricsNilIsZeroOverhead proves a nil *metrics.Metrics
// (metrics.enabled=false) never touches the trust.Metrics registration path —
// the composite must still build and score.
func TestBuildTrustScorer_MetricsNilIsZeroOverhead(t *testing.T) {
	t.Parallel()
	cfg := config.TrustConfig{Enabled: true, Weights: map[string]float64{"geo_risk": 1}}
	scorer, err := BuildTrustScorer(cfg, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildTrustScorer: %v", err)
	}
	if _, err := scorer.Score(context.Background(), trustTestSignals()); err != nil {
		t.Fatalf("Score with nil metrics: %v", err)
	}
}

// TestBuildTrustScorer_MetricsWiredRegistersOnSharedRegistry proves that when
// metrics.enabled (m != nil), the composite records onto m.Registry rather
// than a private one — an operator scraping m.Registry sees sso_trust_score.
func TestBuildTrustScorer_MetricsWiredRegistersOnSharedRegistry(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	cfg := config.TrustConfig{Enabled: true, Weights: map[string]float64{"geo_risk": 1}}
	scorer, err := BuildTrustScorer(cfg, nil, nil, nil, m)
	if err != nil {
		t.Fatalf("BuildTrustScorer: %v", err)
	}
	if _, err := scorer.Score(context.Background(), trustTestSignals()); err != nil {
		t.Fatalf("Score: %v", err)
	}
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "sso_trust_score" {
			found = true
		}
	}
	if !found {
		t.Error("sso_trust_score must be registered on the shared metrics.Metrics.Registry when metrics.enabled")
	}
}

// TestBuildTrustScorer_IPReputationReadsAnomalyStore proves the composition-
// root adapter reuses the SAME anomaly.IPFailureCounter rows the anomaly
// detectors already wrote, hashed via the SAME salted scheme — not a second,
// disconnected IP-hash space.
func TestBuildTrustScorer_IPReputationReadsAnomalyStore(t *testing.T) {
	t.Parallel()
	counter := &fakeIPFailureCounter{}
	salt := []byte("test-salt")
	cfg := config.TrustConfig{
		Enabled: true,
		Weights: map[string]float64{"ip_reputation": 1},
		IPReputation: config.TrustIPReputationConfig{
			FailureThreshold: 1, // any recorded failure trips "suspicious"
		},
	}
	scorer, err := BuildTrustScorer(cfg, counter, nil, salt, nil)
	if err != nil {
		t.Fatalf("BuildTrustScorer: %v", err)
	}
	// Seed the SAME hash the detector-side hashIPForBF would have produced for
	// this ip+salt — proving the adapter computes an identical hash, not an
	// independent one.
	ip := "203.0.113.7"
	counter.total = 5
	counter.distinct = 5
	got, err := scorer.Score(context.Background(), trust.TrustSignals{RemoteIP: ip, Time: time.Now()})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if !counter.calledWithHash(hashIPForTrust(ip, salt)) {
		t.Fatalf("adapter queried counter with a different hash than hashIPForTrust(ip, salt) — hash space mismatch")
	}
	if got.Value >= 0.5 {
		t.Errorf("composite score = %v; want a low (suspicious) score once the shared counter reports high failure volume", got.Value)
	}
}

func trustTestSignals() trust.TrustSignals {
	return trust.TrustSignals{Time: time.Now()}
}

// fakeIPFailureCounter is a minimal anomaly.IPFailureCounter test double
// recording the last hash it was queried with, so the adapter's hash-space
// reuse can be asserted directly.
type fakeIPFailureCounter struct {
	lastHash        string
	total, distinct int
}

func (f *fakeIPFailureCounter) Record(ctx context.Context, ipHash, subjectID string, ts time.Time) error {
	return nil
}

func (f *fakeIPFailureCounter) Count(ctx context.Context, ipHash string, since time.Time) (int, int, error) {
	f.lastHash = ipHash
	return f.total, f.distinct, nil
}

func (f *fakeIPFailureCounter) PruneOlder(ctx context.Context, cutoff time.Time) (int64, error) {
	return 0, nil
}

func (f *fakeIPFailureCounter) calledWithHash(h string) bool { return f.lastHash == h }

var _ anomaly.IPFailureCounter = (*fakeIPFailureCounter)(nil)
