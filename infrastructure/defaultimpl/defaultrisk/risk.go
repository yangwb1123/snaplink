package defaultrisk

import (
	"context"

	"github.com/yangwb1123/snaplink/shared/spi"
)

// NoopRiskScorer always returns spi.DecisionAllow with score 0. The
// zero-overhead default when no risk-scoring backend is configured —
// operators who don't pass sso.WithRiskScorer (server option) get this behavior
// implicitly (the Server's nil-check skips the scorer entirely, no
// instance of this type is ever constructed).
//
// Exposed so tests and downstream code that want an explicit "no
// scoring" wiring (rather than nil) have a typed stand-in.
type NoopRiskScorer struct{}

// Score returns Allow unconditionally. Implements [spi.RiskScorer].
func (NoopRiskScorer) Score(_ context.Context, _ *spi.RiskRequest) (*spi.RiskAssessment, error) {
	return &spi.RiskAssessment{Decision: spi.DecisionAllow}, nil
}

var _ spi.RiskScorer = NoopRiskScorer{}
