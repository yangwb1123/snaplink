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
	if cfg.FeatureGates.Branding == nil || *cfg.FeatureGates.Branding != false {
		t.Errorf("env feature_gates.branding = %v, want explicit false", cfg.FeatureGates.Branding)
	}
}

// TestFeatureGatesConfig_WebSPAAliasNormalization proves the deprecated
// feature_gates.web_spa YAML/env key folds into the canonical Branding field
// (with a warning) instead of surviving as a second source of truth, and
// that setting BOTH keys fails loud.
func TestFeatureGatesConfig_WebSPAAliasNormalization(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "base.yaml", "server:\n  issuer: t\n  listen: :8080\n")
	envSrc := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"SSO_FEATURE_GATES__WEB_SPA=false",
	)}
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p), envSrc)
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	if cfg.FeatureGates.WebSPA != nil {
		t.Errorf("feature_gates.web_spa = %v, want normalized away (nil)", cfg.FeatureGates.WebSPA)
	}
	if cfg.FeatureGates.Branding == nil || *cfg.FeatureGates.Branding != false {
		t.Errorf("feature_gates.branding = %v, want explicit false inherited from web_spa", cfg.FeatureGates.Branding)
	}

	// Both keys set must fail loud rather than silently pick one.
	p2 := writeTemp(t, "both.yaml", "server:\n  issuer: t\n  listen: :8080\nfeature_gates:\n  branding: true\n  web_spa: false\n")
	if _, err := LoadFromSources(context.Background(), NewFileSource(p2)); err == nil {
		t.Fatal("LoadFromSources with both branding and web_spa: want error")
	}
}

// TestAdminConfig_APIRESTEnabledPresenceAwareDefault pins the command-level
// REST default. The field stays a bool for compatibility, so merged-source
// presence must be checked to distinguish an omitted key from false.
func TestAdminConfig_APIRESTEnabledPresenceAwareDefault(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{name: "omitted", body: "admin:\n  enabled: true\n", want: true},
		{name: "explicit true", body: "admin:\n  enabled: true\n  api_rest_enabled: true\n", want: true},
		{name: "explicit false", body: "admin:\n  enabled: true\n  api_rest_enabled: false\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTemp(t, "admin.yaml", "server:\n  issuer: t\n"+tc.body)
			cfg, err := LoadFromSources(context.Background(), NewFileSource(p))
			if err != nil {
				t.Fatalf("LoadFromSources: %v", err)
			}
			if cfg.Admin.APIRESTEnabled != tc.want {
				t.Fatalf("admin.api_rest_enabled = %v, want %v", cfg.Admin.APIRESTEnabled, tc.want)
			}
		})
	}

	p := writeTemp(t, "admin-env.yaml", "server:\n  issuer: t\nadmin:\n  enabled: true\n")
	envSrc := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"SSO_ADMIN__API_REST_ENABLED=false",
	)}
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p), envSrc)
	if err != nil {
		t.Fatalf("LoadFromSources with env override: %v", err)
	}
	if cfg.Admin.APIRESTEnabled {
		t.Fatal("explicit false from the higher-priority env source was defaulted to true")
	}
}
