package config

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type stubSource struct {
	name string
	data map[string]any
	err  error
}

func (s *stubSource) Name() string                                   { return s.name }
func (s *stubSource) Load(_ context.Context) (map[string]any, error) { return s.data, s.err }

func TestDeepMerge_ScalarOverride(t *testing.T) {
	t.Parallel()
	dst := map[string]any{"a": 1, "b": "old"}
	deepMerge(dst, map[string]any{"b": "new", "c": true})
	if dst["a"] != 1 {
		t.Errorf("a = %v want 1 (unchanged)", dst["a"])
	}
	if dst["b"] != "new" {
		t.Errorf("b = %v want new", dst["b"])
	}
	if dst["c"] != true {
		t.Errorf("c = %v want true", dst["c"])
	}
}

func TestDeepMerge_NestedMaps(t *testing.T) {
	t.Parallel()
	dst := map[string]any{
		"server": map[string]any{"listen": ":8080", "issuer": "old"},
	}
	src := map[string]any{
		"server": map[string]any{"listen": ":9090"},
	}
	deepMerge(dst, src)
	srv := dst["server"].(map[string]any)
	if srv["listen"] != ":9090" {
		t.Errorf("listen not overridden: %v", srv["listen"])
	}
	if srv["issuer"] != "old" {
		t.Errorf("issuer should have been preserved: %v", srv["issuer"])
	}
}

func TestDeepMerge_SliceReplaces(t *testing.T) {
	t.Parallel()
	dst := map[string]any{"xs": []any{1, 2, 3}}
	deepMerge(dst, map[string]any{"xs": []any{9}})
	got := dst["xs"].([]any)
	if len(got) != 1 || got[0] != 9 {
		t.Errorf("slice not replaced: %v", got)
	}
}

func TestDeepMerge_TypeMismatchOverwrites(t *testing.T) {
	t.Parallel()
	dst := map[string]any{"x": map[string]any{"y": 1}}
	deepMerge(dst, map[string]any{"x": "now scalar"})
	if dst["x"] != "now scalar" {
		t.Errorf("type-mismatched key not overwritten: %v", dst["x"])
	}
}

func TestLoader_Precedence_LaterWins(t *testing.T) {
	t.Parallel()
	lo := &stubSource{name: "low", data: map[string]any{
		"logging": map[string]any{"level": "info"},
		"server":  map[string]any{"listen": ":8080"},
	}}
	hi := &stubSource{name: "hi", data: map[string]any{
		"logging": map[string]any{"level": "debug"},
	}}
	cfg, err := NewLoader(lo, hi).Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("level = %q want debug (high-priority source)", cfg.Logging.Level)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("listen = %q want :8080 (preserved from low source)", cfg.Server.Listen)
	}
}

func TestLoader_NilSourceData_IsSkipped(t *testing.T) {
	t.Parallel()
	empty := &stubSource{name: "empty", data: nil}
	real := &stubSource{name: "real", data: map[string]any{
		"server": map[string]any{"listen": ":7000"},
	}}
	cfg, err := NewLoader(empty, real).Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":7000" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
}

func TestLoader_SourceError_ShortCircuits(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	_, err := NewLoader(&stubSource{name: "bad", err: boom}).Load(context.Background())
	if err == nil || !errors.Is(err, boom) {
		t.Errorf("err = %v want wrapping boom", err)
	}
}

func TestLoader_ValidationStillRuns(t *testing.T) {
	t.Parallel()
	// Invalid logging.level should still fail through the Loader path
	// (regression guard — applyDefaults + validate must run on the merged result).
	bad := &stubSource{name: "x", data: map[string]any{
		"logging": map[string]any{"level": "verbose"},
	}}
	_, err := NewLoader(bad).Load(context.Background())
	if err == nil {
		t.Errorf("expected validation error for bogus log level")
	}
}

func TestLoader_DefaultsApplied(t *testing.T) {
	t.Parallel()
	// Empty merge → applyDefaults should populate the documented defaults.
	cfg, err := NewLoader(&stubSource{name: "empty"}).Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("default log level not applied: %q", cfg.Logging.Level)
	}
	if cfg.Server.Issuer == "" {
		t.Errorf("default issuer not applied")
	}
}

// TestLoader_UnknownKey_Warns verifies that unknown YAML keys produce a
// warning log instead of silently defaulting. The config itself still
// loads successfully — this is the graceful-fallback contract.
func TestLoader_UnknownKey_Warns(t *testing.T) {
	t.Parallel()
	// Capture slog output.
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(oldLogger)

	src := &stubSource{name: "typo", data: map[string]any{
		"server": map[string]any{
			"listen":       ":9090",
			"typo_listen":  ":8080", // unknown key (should trigger warning)
			"sesssion_ttl": "30m",   // unknown key (triple-s typo)
		},
		"unknown_section": map[string]any{"a": 1}, // unknown top-level key
	}}

	cfg, err := NewLoader(src).Load(context.Background())
	if err != nil {
		t.Fatalf("Load should succeed even with unknown keys, got: %v", err)
	}
	// Known keys should still be parsed correctly.
	if cfg.Server.Listen != ":9090" {
		t.Errorf("known key server.listen = %q, want :9090", cfg.Server.Listen)
	}

	logged := buf.String()
	t.Logf("captured slog output:\n%s", logged)

	// The warning MUST mention at least one unknown key.
	// Note: goccy/go-yaml stops at the first unknown field, so we
	// won't necessarily see *all* keys in a single warning — but
	// at least one actionable message is guaranteed.
	if !strings.Contains(logged, "unknown") {
		t.Error("expected slog warning about unknown keys, got none")
	}
}
