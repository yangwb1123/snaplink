package trust

import (
	"context"
	"strings"
)

// Score buckets a country falls into. Deny takes precedence over trust (a
// country cannot be both denied and trusted at once — mirrors
// config.RiskConfig's deny-before-allow evaluation order).
const (
	geoScoreUnknown = 0.5
	geoScoreKnown   = 0.7
	geoScoreTrusted = 0.95
	geoScoreDenied  = 0.05
)

// GeoRiskScorer scores trust from the geo enrichment already computed for
// the request. It follows the same UX-only, fail-open contract geo
// enrichment does elsewhere (AGENTS.md "Fail Modes") — Score NEVER errors,
// and an empty/unknown country is a neutral cold-start signal, not a
// penalty.
//
// Deployments wanting a hard country-based deny/allow DECISION already have
// shared/spi.RiskScorer + config.RiskConfig for that; GeoRiskScorer instead
// produces an ADVISORY signal for the composite.
type GeoRiskScorer struct {
	// TrustedCountries / DeniedCountries are ISO 3166-1 alpha-2 codes,
	// compared case-insensitively. Both nil is a valid configuration — every
	// known country scores geoScoreKnown.
	TrustedCountries []string
	DeniedCountries  []string
}

// NewGeoRiskScorer builds a GeoRiskScorer from operator-configured country
// lists (config.TrustGeoConfig.TrustedCountries / DeniedCountries).
func NewGeoRiskScorer(trustedCountries, deniedCountries []string) *GeoRiskScorer {
	return &GeoRiskScorer{TrustedCountries: trustedCountries, DeniedCountries: deniedCountries}
}

// Name implements TrustScorer.
func (s *GeoRiskScorer) Name() string { return "geo_risk" }

// Score implements TrustScorer.
func (s *GeoRiskScorer) Score(_ context.Context, signals TrustSignals) (TrustScore, error) {
	country := signals.Geo.CountryCode
	if country == "" {
		return TrustScore{Value: geoScoreUnknown, Reasons: []string{"geo_risk:unknown_country"}}, nil
	}
	if containsCountryFold(s.DeniedCountries, country) {
		return TrustScore{Value: geoScoreDenied, Reasons: []string{"geo_risk:denied_country"}}, nil
	}
	if containsCountryFold(s.TrustedCountries, country) {
		return TrustScore{Value: geoScoreTrusted, Reasons: []string{"geo_risk:trusted_country"}}, nil
	}
	return TrustScore{Value: geoScoreKnown, Reasons: []string{"geo_risk:known_country"}}, nil
}

func containsCountryFold(codes []string, country string) bool {
	for _, c := range codes {
		if strings.EqualFold(c, country) {
			return true
		}
	}
	return false
}

var _ TrustScorer = (*GeoRiskScorer)(nil)
