package trust

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metric names, prefixed sso_ per the SDK-wide convention (see
// platform/metrics/consts.go) so they never collide with metrics an
// embedding application emits on the same registry.
const (
	NameTrustScore       = "sso_trust_score"
	NameTrustScoreErrors = "sso_trust_scorer_errors_total"
)

const labelScorer = "scorer"

// Metrics groups the trust-scoring Prometheus collectors. It is
// deliberately self-contained (imports client_golang directly) rather than
// a field on platform/metrics.Metrics: this package lives at the shared/
// (kernel) layer and platform/ sits ABOVE it in the dependency direction
// (architecture_layer_test.go), so shared/trust must not import
// platform/metrics. A nil *Metrics is the "not wired" state —
// WeightedComposite treats every method as a no-op, so scoring has zero
// overhead until an operator opts in (mirrors sso.WithMetrics being
// entirely optional).
type Metrics struct {
	// Score is a histogram of every scorer's returned Value — including the
	// composite's own aggregate under scorer="composite" — labeled by
	// scorer name. Operators graph the distribution shape (a wall of 1.0s
	// vs. a spread) rather than a single quantile.
	Score *prometheus.HistogramVec // labels: scorer

	// ScoreErrors counts scorer failures that degraded to FloorOnError, by
	// scorer name. Sustained non-zero means a scorer's data source is
	// unreachable; the login path is unaffected (fail-open) but the
	// composite is running on floors instead of real signal for that
	// scorer.
	ScoreErrors *prometheus.CounterVec // labels: scorer
}

// NewMetrics registers the trust-scoring collectors on reg — pass a fresh
// *prometheus.Registry, or an existing one when embedding alongside
// sso.WithMetrics (mirrors platform/metrics.Metrics.Registry).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	factory := promauto.With(reg)
	return &Metrics{
		Score: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    NameTrustScore,
			Help:    "Trust score (0.0-1.0) returned by each configured scorer, including the composite aggregate (scorer=\"composite\").",
			Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		}, []string{labelScorer}),
		ScoreErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Name: NameTrustScoreErrors,
			Help: "Trust scorer failures that degraded to their configured floor, by scorer name.",
		}, []string{labelScorer}),
	}
}
