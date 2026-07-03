package config

import (
	"context"
	"testing"
)

// TestFeatureGatesConfig_YAMLExplicitFalse proves an explicit `false` in YAML
// round-trips to a non-nil *bool pointing at false (distinguishable from the
// omitted-key nil case tested below).
func TestFeatureGatesConfig_YAMLExplicitFalse(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "gates.yaml", `
server:
  issuer: t
  listen: :8080
feature_gates:
  oidc: false
  admin_api: false
  ciba: true
`)
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	if cfg.FeatureGates.OIDC == nil || *cfg.FeatureGates.OIDC != false {
		t.Errorf("feature_gates.oidc = %v, want explicit false", cfg.FeatureGates.OIDC)
	}
	if cfg.FeatureGates.AdminAPI == nil || *cfg.FeatureGates.AdminAPI != false {
		t.Errorf("feature_gates.admin_api = %v, want explicit false", cfg.FeatureGates.AdminAPI)
	}
	if cfg.FeatureGates.CIBA == nil || *cfg.FeatureGates.CIBA != true {
		t.Errorf("feature_gates.ciba = %v, want explicit true", cfg.FeatureGates.CIBA)
	}
	// Untouched keys stay nil (not defaulted to true/false) so the SDK's own
	// nil-means-on resolution is what applies.
	if cfg.FeatureGates.CAEP != nil {
		t.Errorf("feature_gates.caep = %v, want nil (untouched key)", cfg.FeatureGates.CAEP)
	}

	opts := cfg.ServerOptions()
	if len(opts) == 0 {
		t.Fatal("ServerOptions returned no options")
	}
}

// TestFeatureGatesConfig_OmittedIsByteIdentical proves that omitting
// feature_gates entirely leaves every field nil AND does not add a
// sso.WithFeatureGates call to ServerOptions() — the option is skipped
// entirely (not just a no-op call) so a build predating FeatureGates sees an
// identical option list.
func TestFeatureGatesConfig_OmittedIsByteIdentical(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "no-gates.yaml", "server:\n  issuer: t\n  listen: :8080\n")
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	if cfg.FeatureGates.anySet() {
		t.Errorf("feature_gates should be entirely unset: %+v", cfg.FeatureGates)
	}
	withoutGates := cfg.ServerOptions()

	// A config that explicitly sets one key must yield exactly ONE more
	// option than the all-nil baseline above.
	p2 := writeTemp(t, "one-gate.yaml", "server:\n  issuer: t\n  listen: :8080\nfeature_gates:\n  oidc: false\n")
	cfg2, err := LoadFromSources(context.Background(), NewFileSource(p2))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	withGate := cfg2.ServerOptions()
	if len(withGate) != len(withoutGates)+1 {
		t.Errorf("got %d opts with one gate set, %d without — want exactly +1", len(withGate), len(withoutGates))
	}
}

// TestFeatureGatesConfig_EnvOverride proves feature_gates follows the same
// SSO_<PREFIX>__ env convention as every other config section (no bespoke
// env-parsing code needed — the generic EnvSource + YAML round-trip handles
// the *bool fields like any other typed field).
func TestFeatureGatesConfig_EnvOverride(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "base.yaml", "server:\n  issuer: t\n  listen: :8080\n")
	envSrc := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"SSO_FEATURE_GATES__OIDC=false",
		"SSO_FEATURE_GATES__WEB_SPA=false",
	)}
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p), envSrc)
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	if cfg.FeatureGates.OIDC == nil || *cfg.FeatureGates.OIDC != false {
		t.Errorf("env feature_gates.oidc = %v, want explicit false", cfg.FeatureGates.OIDC)
	}
	if cfg.FeatureGates.WebSPA == nil || *cfg.FeatureGates.WebSPA != false {
		t.Errorf("env feature_gates.web_spa = %v, want explicit false", cfg.FeatureGates.WebSPA)
	}
}
