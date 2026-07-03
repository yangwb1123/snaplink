package trust_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/trust"
)

func TestGeoRiskScorer_Boundaries(t *testing.T) {
	scorer := trust.NewGeoRiskScorer([]string{"US", "ca"}, []string{"KP"})
	ctx := context.Background()

	cases := []struct {
		name        string
		country     string
		wantReason  string
		wantMinimum float64
		wantMaximum float64
	}{
		{"empty_country_is_unknown_not_denied", "", "geo_risk:unknown_country", 0.5, 0.5},
		{"denied_country", "KP", "geo_risk:denied_country", 0, 0.2},
		{"trusted_country_exact_case", "US", "geo_risk:trusted_country", 0.8, 1},
		{"trusted_country_case_insensitive", "CA", "geo_risk:trusted_country", 0.8, 1},
		{"known_country_neither_list", "DE", "geo_risk:known_country", 0.5, 0.8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, err := scorer.Score(ctx, trust.TrustSignals{Geo: core.GeoInfo{CountryCode: tc.country}})
			if err != nil {
				t.Fatalf("Score returned error: %v", err)
			}
			if score.Value < tc.wantMinimum || score.Value > tc.wantMaximum {
				t.Fatalf("Value = %v, want in [%v, %v]", score.Value, tc.wantMinimum, tc.wantMaximum)
			}
			if len(score.Reasons) != 1 || score.Reasons[0] != tc.wantReason {
				t.Fatalf("Reasons = %v, want [%s]", score.Reasons, tc.wantReason)
			}
		})
	}
}

func TestGeoRiskScorer_DenyTakesPrecedenceOverTrust(t *testing.T) {
	// A country in BOTH lists must deny — mirrors config.RiskConfig's
	// deny-before-allow evaluation order (AGENTS.md).
	scorer := trust.NewGeoRiskScorer([]string{"XX"}, []string{"XX"})
	score, err := scorer.Score(context.Background(), trust.TrustSignals{Geo: core.GeoInfo{CountryCode: "XX"}})
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}
	if score.Reasons[0] != "geo_risk:denied_country" {
		t.Fatalf("Reasons = %v, want deny to win", score.Reasons)
	}
}

func TestGeoRiskScorer_Name(t *testing.T) {
	if got := (&trust.GeoRiskScorer{}).Name(); got != "geo_risk" {
		t.Fatalf("Name() = %q, want geo_risk", got)
	}
}
