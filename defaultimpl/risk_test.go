package defaultimpl_test

import "github.com/snaplink/sso/spi"

import (
	"context"
	"testing"

	"github.com/snaplink/sso/defaultimpl"
)

func TestNoopRiskScorer_AlwaysAllows(t *testing.T) {
	got, err := defaultimpl.NoopRiskScorer{}.Score(context.Background(), &spi.RiskRequest{
		SubjectID: "alice",
		ClientID:  "web-app",
		Provider:  "password",
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got.Decision != spi.DecisionAllow {
		t.Errorf("Decision = %q, want Allow", got.Decision)
	}
	if got.Score != 0 {
		t.Errorf("Score = %d, want 0", got.Score)
	}
}

func TestNoopRiskScorer_NilRequest_StillAllows(t *testing.T) {
	// Defensive: the noop should not panic on a nil request even though
	// the server wouldn't normally call it that way.
	got, err := defaultimpl.NoopRiskScorer{}.Score(context.Background(), nil)
	if err != nil {
		t.Fatalf("Score(nil): %v", err)
	}
	if got.Decision != spi.DecisionAllow {
		t.Errorf("Decision = %q, want Allow", got.Decision)
	}
}

// Compile-time guard: defaultimpl.NoopRiskScorer satisfies spi.RiskScorer.
var _ spi.RiskScorer = defaultimpl.NoopRiskScorer{}
