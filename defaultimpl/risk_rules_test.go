package defaultimpl_test

import "github.com/snaplink/sso/spi"

import (
	"context"
	"testing"

	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/geo"
)

func TestRuleBasedRiskScorer_AllowsByDefault(t *testing.T) {
	s, err := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	a, _ := s.Score(context.Background(), &spi.RiskRequest{RemoteIP: "203.0.113.5"})
	if a.Decision != spi.DecisionAllow {
		t.Fatalf("Decision = %s; want allow", a.Decision)
	}
}

func TestRuleBasedRiskScorer_DeniesIPInExactList(t *testing.T) {
	s, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		IPDenyList: []string{"203.0.113.5"},
	})
	a, _ := s.Score(context.Background(), &spi.RiskRequest{RemoteIP: "203.0.113.5"})
	if a.Decision != spi.DecisionDeny {
		t.Fatalf("Decision = %s; want deny", a.Decision)
	}
	if a.Reason == "" {
		t.Error("expected non-empty Reason on deny for posthoc audit search")
	}
}

func TestRuleBasedRiskScorer_DeniesIPInCIDR(t *testing.T) {
	s, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		IPDenyList: []string{"203.0.113.0/24"},
	})
	a, _ := s.Score(context.Background(), &spi.RiskRequest{RemoteIP: "203.0.113.42"})
	if a.Decision != spi.DecisionDeny {
		t.Fatalf("CIDR match should deny; got %s", a.Decision)
	}
}

func TestRuleBasedRiskScorer_IPAllowListDefaultDeny(t *testing.T) {
	s, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		IPAllowList: []string{"10.0.0.0/8", "192.0.2.1"},
	})
	allowed, _ := s.Score(context.Background(), &spi.RiskRequest{RemoteIP: "10.5.4.3"})
	if allowed.Decision != spi.DecisionAllow {
		t.Errorf("CIDR-matching allow IP got %s; want allow", allowed.Decision)
	}
	exact, _ := s.Score(context.Background(), &spi.RiskRequest{RemoteIP: "192.0.2.1"})
	if exact.Decision != spi.DecisionAllow {
		t.Errorf("exact allow IP got %s; want allow", exact.Decision)
	}
	denied, _ := s.Score(context.Background(), &spi.RiskRequest{RemoteIP: "203.0.113.5"})
	if denied.Decision != spi.DecisionDeny {
		t.Errorf("non-allowed IP got %s; want deny (default-deny under non-empty allow list)", denied.Decision)
	}
}

func TestRuleBasedRiskScorer_DenyListBeatsAllowList(t *testing.T) {
	s, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		IPDenyList:  []string{"10.0.0.0/8"},
		IPAllowList: []string{"10.0.0.0/8"},
	})
	a, _ := s.Score(context.Background(), &spi.RiskRequest{RemoteIP: "10.5.4.3"})
	if a.Decision != spi.DecisionDeny {
		t.Fatalf("deny rules MUST short-circuit allow rules; got %s", a.Decision)
	}
}

func TestRuleBasedRiskScorer_DeniesCountryInDenyList(t *testing.T) {
	s, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		CountryDenyList: []string{"RU"},
	})
	a, _ := s.Score(context.Background(), &spi.RiskRequest{
		RemoteIP: "203.0.113.5",
		Geo:      &geo.GeoInfo{CountryCode: "ru"}, // lowercase intentional
	})
	if a.Decision != spi.DecisionDeny {
		t.Fatalf("Decision = %s; want deny (country compare is case-insensitive)", a.Decision)
	}
}

func TestRuleBasedRiskScorer_CountryAllowListGeoMissing(t *testing.T) {
	// Default DenyOnGeoMissing=false: missing geo skips the allow
	// list (operators don't want to lock out every login when the
	// geo provider has a hiccup).
	s, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		CountryAllowList: []string{"US"},
	})
	a, _ := s.Score(context.Background(), &spi.RiskRequest{RemoteIP: "203.0.113.5"})
	if a.Decision != spi.DecisionAllow {
		t.Fatalf("default DenyOnGeoMissing=false should let request through when no geo; got %s", a.Decision)
	}

	// DenyOnGeoMissing=true: missing geo blocks. Operators who
	// genuinely require geo-restriction need this strict mode.
	strict, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		CountryAllowList: []string{"US"},
		DenyOnGeoMissing: true,
	})
	denied, _ := strict.Score(context.Background(), &spi.RiskRequest{RemoteIP: "203.0.113.5"})
	if denied.Decision != spi.DecisionDeny {
		t.Fatalf("DenyOnGeoMissing=true should reject when geo absent; got %s", denied.Decision)
	}
}

func TestRuleBasedRiskScorer_CountryAllowListPasses(t *testing.T) {
	s, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		CountryAllowList: []string{"US", "DE"},
	})
	a, _ := s.Score(context.Background(), &spi.RiskRequest{
		RemoteIP: "203.0.113.5",
		Geo:      &geo.GeoInfo{CountryCode: "DE"},
	})
	if a.Decision != spi.DecisionAllow {
		t.Fatalf("Decision = %s; want allow", a.Decision)
	}
}

func TestRuleBasedRiskScorer_MalformedIPEntriesError(t *testing.T) {
	if _, err := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		IPDenyList: []string{"not-an-ip"},
	}); err == nil {
		t.Fatal("expected error on malformed IPDenyList entry — misconfigs MUST fail at boot")
	}
}

func TestRuleBasedRiskScorer_RemoteIPWithPort(t *testing.T) {
	// RemoteIP sometimes arrives with a :port suffix (raw RemoteAddr
	// from net/http). The scorer must normalize before matching.
	s, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		IPDenyList: []string{"203.0.113.5"},
	})
	a, _ := s.Score(context.Background(), &spi.RiskRequest{RemoteIP: "203.0.113.5:5432"})
	if a.Decision != spi.DecisionDeny {
		t.Fatalf("Decision = %s; want deny (port suffix should be stripped)", a.Decision)
	}
}

func TestRuleBasedRiskScorer_NilRequestAllows(t *testing.T) {
	// Defensive — the wire path never passes nil, but the contract
	// shouldn't panic on a degenerate caller.
	s, _ := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		IPDenyList: []string{"0.0.0.0/0"},
	})
	a, _ := s.Score(context.Background(), nil)
	if a.Decision != spi.DecisionAllow {
		t.Fatalf("nil request should fall through to Allow; got %s", a.Decision)
	}
}
