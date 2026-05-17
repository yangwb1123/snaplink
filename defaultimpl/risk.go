package defaultimpl

import (
	"context"

	"github.com/snaplink/sso"
)

// NoopRiskScorer always returns sso.DecisionAllow with score 0. The
// zero-overhead default when no risk-scoring backend is configured —
// operators who don't pass [sso.WithRiskScorer] get this behavior
// implicitly (the Server's nil-check skips the scorer entirely, no
// instance of this type is ever constructed).
//
// Exposed so tests and downstream code that want an explicit "no
// scoring" wiring (rather than nil) have a typed stand-in.
type NoopRiskScorer struct{}

// Score returns Allow unconditionally. Implements [sso.RiskScorer].
func (NoopRiskScorer) Score(_ context.Context, _ *sso.RiskRequest) (*sso.RiskAssessment, error) {
	return &sso.RiskAssessment{Decision: sso.DecisionAllow}, nil
}

var _ sso.RiskScorer = NoopRiskScorer{}
