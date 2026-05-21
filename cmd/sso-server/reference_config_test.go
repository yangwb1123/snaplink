package main

import (
	"testing"

	"github.com/snaplink/sso/config"
)

// TestReferenceConfigYAMLParses guards the cmd's reference YAML
// against drift. Operators copy this file as their starting point;
// a typo or stale schema reference here breaks first-touch UX. The
// loader applies the full validation chain (defaults + sub-section
// parsing), so a green result means every top-level + nested key
// the reference advertises maps cleanly onto the Go struct tree.
func TestReferenceConfigYAMLParses(t *testing.T) {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		t.Fatalf("reference YAML failed to load: %v", err)
	}
	// Spot-check that the major sections actually round-tripped — a
	// silently-dropped top-level key would parse without error but
	// leave the corresponding struct zero, and operators reading the
	// reference would assume the knob took effect.
	checks := map[string]bool{
		"admin enabled":             cfg.Admin.Enabled,
		"audit enabled":             cfg.Audit.Enabled,
		"permissions embedded":      cfg.Permissions.EmbedInLogin,
		"network enabled":           cfg.Network.Enabled,
		"metrics enabled":           cfg.Metrics.Enabled,
		"identity backend defined":  cfg.Identity.Backend != "",
		"registry tags populated":   len(cfg.Registry.ServiceTags) > 0,
	}
	for k, v := range checks {
		if !v {
			t.Errorf("reference YAML left %q at zero value; section likely missing or mis-keyed", k)
		}
	}
}
