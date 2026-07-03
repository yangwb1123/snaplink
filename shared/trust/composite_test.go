package trust_test

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/snaplink/sso/shared/trust"
)

// fixedScorer is a hand-rolled TrustScorer stub (not a mocking framework) —
// TrustScorer is a brand-new SPI with no Memory* reference implementation to
// reuse, so a small deterministic fake is the direct equivalent of the
// Memory* stores used elsewhere in the codebase.
type fixedScorer struct {
	name  string
	score trust.TrustScore
	err   error
}

func (f fixedScorer) Name() string { return f.name }
func (f fixedScorer) Score(context.Context, trust.TrustSignals) (trust.TrustScore, error) {
	return f.score, f.err
}

func TestWeightedComposite_NoScorersConfigured(t *testing.T) {
	composite := trust.NewWeightedComposite(nil, nil)
	_, err := composite.Score(context.Background(), trust.TrustSignals{})
	if !errors.Is(err, trust.ErrNoScorers) {
		t.Fatalf("err = %v, want ErrNoScorers", err)
	}
}

func TestWeightedComposite_ZeroWeightSum(t *testing.T) {
	weights := []trust.ScorerWeight{
		{Scorer: fixedScorer{name: "a", score: trust.TrustScore{Value: 1}}, Weight: 0},
	}
	composite := trust.NewWeightedComposite(weights, nil)
	_, err := composite.Score(context.Background(), trust.TrustSignals{})
	if !errors.Is(err, trust.ErrNoWeight) {
		t.Fatalf("err = %v, want ErrNoWeight", err)
	}
}

func TestWeightedComposite_WeightedAverageMath(t *testing.T) {
	// weight 3 * 0.9 + weight 1 * 0.1 = 2.8 / 4 = 0.7
	weights := []trust.ScorerWeight{
		{Scorer: fixedScorer{name: "heavy", score: trust.TrustScore{Value: 0.9, Reasons: []string{"heavy:ok"}}}, Weight: 3},
		{Scorer: fixedScorer{name: "light", score: trust.TrustScore{Value: 0.1, Reasons: []string{"light:bad"}}}, Weight: 1},
	}
	composite := trust.NewWeightedComposite(weights, nil)
	score, err := composite.Score(context.Background(), trust.TrustSignals{})
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}
	if math.Abs(score.Value-0.7) > 1e-9 {
		t.Fatalf("Value = %v, want 0.7", score.Value)
	}
	if len(score.Reasons) != 2 {
		t.Fatalf("Reasons = %v, want both scorers' reasons folded in", score.Reasons)
	}
}

func TestWeightedComposite_ScorerErrorDegradesToFloor(t *testing.T) {
	weights := []trust.ScorerWeight{
		{Scorer: fixedScorer{name: "ok", score: trust.TrustScore{Value: 1.0}}, Weight: 1},
		{
			Scorer:       fixedScorer{name: "flaky", err: errors.New("store down")},
			Weight:       1,
			FloorOnError: 0.4,
		},
	}
	composite := trust.NewWeightedComposite(weights, nil)
	score, err := composite.Score(context.Background(), trust.TrustSignals{})
	if err != nil {
		t.Fatalf("Score returned error: %v (a single scorer's error must NOT fail the composite)", err)
	}
	// (1.0*1 + 0.4*1) / 2 = 0.7
	if math.Abs(score.Value-0.7) > 1e-9 {
		t.Fatalf("Value = %v, want 0.7 (floor applied for the failed scorer)", score.Value)
	}
	foundDegraded := false
	for _, r := range score.Reasons {
		if r == "flaky:degraded" {
			foundDegraded = true
		}
	}
	if !foundDegraded {
		t.Fatalf("Reasons = %v, want a flaky:degraded marker", score.Reasons)
	}
}

func TestWeightedComposite_DegradationRecordsMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := trust.NewMetrics(reg)
	weights := []trust.ScorerWeight{
		{Scorer: fixedScorer{name: "ok", score: trust.TrustScore{Value: 0.8}}, Weight: 1},
		{Scorer: fixedScorer{name: "flaky", err: errors.New("down")}, Weight: 1, FloorOnError: 0.5},
	}
	composite := trust.NewWeightedComposite(weights, metrics)
	if _, err := composite.Score(context.Background(), trust.TrustSignals{}); err != nil {
		t.Fatalf("Score returned error: %v", err)
	}

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	errCount := 0.0
	for _, mf := range mfs {
		if mf.GetName() != trust.NameTrustScoreErrors {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "scorer" && lp.GetValue() == "flaky" {
					errCount = m.GetCounter().GetValue()
				}
			}
		}
	}
	if errCount != 1 {
		t.Fatalf("flaky scorer error count = %v, want 1", errCount)
	}
}

func TestWeightedComposite_ClampsOutOfRangeScorerValue(t *testing.T) {
	weights := []trust.ScorerWeight{
		{Scorer: fixedScorer{name: "buggy", score: trust.TrustScore{Value: 5.0}}, Weight: 1},
	}
	composite := trust.NewWeightedComposite(weights, nil)
	score, err := composite.Score(context.Background(), trust.TrustSignals{})
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}
	if score.Value != 1 {
		t.Fatalf("Value = %v, want clamped to 1", score.Value)
	}
}

func TestWeightedComposite_Name(t *testing.T) {
	if got := trust.NewWeightedComposite(nil, nil).Name(); got != "composite" {
		t.Fatalf("Name() = %q, want composite", got)
	}
}
