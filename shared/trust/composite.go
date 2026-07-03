package trust

import (
	"context"
	"errors"
)

// ErrNoScorers is returned by WeightedComposite.Score when no scorers are
// configured — there is nothing to aggregate.
var ErrNoScorers = errors.New("trust: composite has no scorers configured")

// ErrNoWeight is returned when every configured scorer's weight sums to <=
// 0 — there is nothing to average, so returning a synthetic score would be
// misleading rather than a real signal.
var ErrNoWeight = errors.New("trust: composite scorer weights sum to zero")

// WeightedComposite implements TrustScorer by combining N named scorers
// with per-scorer weights. A scorer that errors degrades to its configured
// FloorOnError rather than failing the whole composite — fail-open, per
// AGENTS.md "Fail Modes" (matches the geo/risk-scorer precedent). Metrics
// (optional; nil = no-op) records both the observed value and the
// degradation so a flaky data source is visible without ever blocking the
// login it was scoring.
type WeightedComposite struct {
	weights []ScorerWeight
	metrics *Metrics
}

// NewWeightedComposite builds a composite over weights. metrics may be nil
// (no metrics emitted — zero overhead, matching the SDK-wide opt-in metrics
// pattern).
func NewWeightedComposite(weights []ScorerWeight, metrics *Metrics) *WeightedComposite {
	return &WeightedComposite{weights: weights, metrics: metrics}
}

// Name implements TrustScorer; useful when a composite is itself nested
// inside another aggregation (e.g. Reasons prefixing, metrics labeling).
func (c *WeightedComposite) Name() string { return "composite" }

// Score aggregates every configured scorer's contribution. It returns an
// error from the COMPOSITE ITSELF only — never propagates a single
// scorer's error, which is absorbed into that scorer's FloorOnError instead.
func (c *WeightedComposite) Score(ctx context.Context, signals TrustSignals) (TrustScore, error) {
	if len(c.weights) == 0 {
		return TrustScore{}, ErrNoScorers
	}
	var weightedSum, weightTotal float64
	var reasons []string
	for _, sw := range c.weights {
		val, r := c.scoreOne(ctx, signals, sw)
		weightedSum += val * sw.Weight
		weightTotal += sw.Weight
		reasons = append(reasons, r...)
	}
	if weightTotal <= 0 {
		return TrustScore{Reasons: reasons}, ErrNoWeight
	}
	final := ClampScore(weightedSum / weightTotal)
	c.recordObserved(c.Name(), final)
	return TrustScore{Value: final, Reasons: reasons}, nil
}

// scoreOne evaluates a single weighted scorer, applying the fail-open floor
// on error and recording metrics. Split out of Score to keep both under the
// function-length/complexity budget.
func (c *WeightedComposite) scoreOne(ctx context.Context, signals TrustSignals, sw ScorerWeight) (float64, []string) {
	name := sw.Scorer.Name()
	score, err := sw.Scorer.Score(ctx, signals)
	if err != nil {
		c.recordError(name)
		return ClampScore(sw.FloorOnError), []string{name + ":degraded"}
	}
	c.recordObserved(name, score.Value)
	return ClampScore(score.Value), score.Reasons
}

func (c *WeightedComposite) recordError(name string) {
	if c.metrics == nil || c.metrics.ScoreErrors == nil {
		return
	}
	c.metrics.ScoreErrors.WithLabelValues(name).Inc()
}

func (c *WeightedComposite) recordObserved(name string, value float64) {
	if c.metrics == nil || c.metrics.Score == nil {
		return
	}
	c.metrics.Score.WithLabelValues(name).Observe(ClampScore(value))
}

var _ TrustScorer = (*WeightedComposite)(nil)
