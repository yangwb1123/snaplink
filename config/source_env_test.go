package config

import (
	"context"
	"testing"
)

func envFn(pairs ...string) func() []string {
	return func() []string { return pairs }
}

func TestEnvSource_PrefixFilter(t *testing.T) {
	t.Parallel()
	src := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"PATH=/usr/bin",
		"SSO_LOGGING__LEVEL=debug",
		"OTHER_FOO=bar",
	)}
	m, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := m["path"]; ok {
		t.Errorf("non-prefixed var leaked: %v", m)
	}
	if _, ok := m["other_foo"]; ok {
		t.Errorf("wrong-prefix var leaked: %v", m)
	}
	logging, _ := m["logging"].(map[string]any)
	if logging["level"] != "debug" {
		t.Errorf("level = %v", logging)
	}
}

func TestEnvSource_NestedPath(t *testing.T) {
	t.Parallel()
	src := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"SSO_SNAPSHOT__STORAGE__BACKEND=file",
	)}
	m, _ := src.Load(context.Background())
	snap := m["snapshot"].(map[string]any)
	storage := snap["storage"].(map[string]any)
	if storage["backend"] != "file" {
		t.Errorf("backend = %v", storage["backend"])
	}
}

func TestEnvSource_TypeCoercion(t *testing.T) {
	t.Parallel()
	src := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"SSO_BOOTSTRAP__DISABLED=true",
		"SSO_AUDIT__MEMORY_CAPACITY=512",
	)}
	m, _ := src.Load(context.Background())
	boot := m["bootstrap"].(map[string]any)
	if boot["disabled"] != true {
		t.Errorf("disabled = %v (%T) want bool true", boot["disabled"], boot["disabled"])
	}
	audit := m["audit"].(map[string]any)
	// yaml parses "512" as int (uint64 or int depending on impl); accept any numeric.
	switch v := audit["memory_capacity"].(type) {
	case int, int64, uint64, float64:
		// ok
	default:
		t.Errorf("memory_capacity = %v (%T) want numeric", v, v)
	}
}

func TestEnvSource_EmptyValue(t *testing.T) {
	t.Parallel()
	src := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"SSO_LOGGING__LEVEL=",
	)}
	m, _ := src.Load(context.Background())
	logging := m["logging"].(map[string]any)
	if logging["level"] != "" {
		t.Errorf("empty ENV should yield empty string, got %v", logging["level"])
	}
}

func TestEnvSource_NoMatchingVars_ReturnsNil(t *testing.T) {
	t.Parallel()
	src := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"PATH=/usr/bin",
	)}
	m, _ := src.Load(context.Background())
	if m != nil {
		t.Errorf("no matches should yield nil map, got %v", m)
	}
}

func TestEnvSource_DefaultsApplied(t *testing.T) {
	t.Parallel()
	src := NewEnvSource()
	if src.Prefix != DefaultEnvPrefix || src.Separator != DefaultEnvSeparator {
		t.Errorf("defaults missing: %+v", src)
	}
}

func TestEnvSource_OverridesFileSource(t *testing.T) {
	t.Parallel()
	// End-to-end: file says listen :8080, env overrides to :9999.
	p := writeTemp(t, "base.yaml", "server:\n  listen: :8080\n")
	envSrc := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"SSO_SERVER__LISTEN=:9999",
	)}
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p), envSrc)
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	if cfg.Server.Listen != ":9999" {
		t.Errorf("env override failed: listen = %q", cfg.Server.Listen)
	}
}

func TestEnvSource_BadKVPair_Ignored(t *testing.T) {
	t.Parallel()
	// No '=' in the pair — strings.Cut returns ok=false; we skip.
	src := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"NOEQUALSIGN",
		"SSO_LOGGING__LEVEL=info",
	)}
	m, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	logging := m["logging"].(map[string]any)
	if logging["level"] != "info" {
		t.Errorf("level = %v", logging["level"])
	}
}
