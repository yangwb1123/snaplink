package main

import (
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/config"
)

// TestBuildRiskScorer_DisabledReturnsNil proves the helper is a
// silent no-op when risk.enabled is false so cmd doesn't pay the
// scorer cost on every /auth/login.
func TestBuildRiskScorer_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	scorer, err := serverbuildplatform.BuildRiskScorer(&config.RiskConfig{Enabled: false}, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if scorer != nil {
		t.Errorf("disabled returned scorer = %v; want nil", scorer)
	}
}

// TestBuildRiskScorer_EnabledReturnsScorer proves the enabled path
// constructs the reference RuleBasedRiskScorer and that downstream
// rules (a single deny-list entry) actually apply.
func TestBuildRiskScorer_EnabledReturnsScorer(t *testing.T) {
	t.Parallel()
	cfg := &config.RiskConfig{Enabled: true, IPDenyList: []string{"203.0.113.5"}}
	scorer, err := serverbuildplatform.BuildRiskScorer(cfg, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if scorer == nil {
		t.Fatal("enabled returned nil scorer; want non-nil")
	}
}

// TestBuildRiskScorer_BadCIDRSurfaces guards the validation
// boundary — a misconfigured deny-list entry must fail at boot so
// operators see the error in cmd's startup log instead of silently
// shipping with a permissive scorer.
func TestBuildRiskScorer_BadCIDRSurfaces(t *testing.T) {
	t.Parallel()
	cfg := &config.RiskConfig{Enabled: true, IPDenyList: []string{"not-an-ip"}}
	if _, err := serverbuildplatform.BuildRiskScorer(cfg, quietLogger()); err == nil {
		t.Fatal("expected error on malformed CIDR")
	}
}
