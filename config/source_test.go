package config

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestLoader_YAMLAnchorAmplification_FailsFastNotHangs is a regression test
// for a billion-laughs-style YAML anchor/alias amplification DoS:
// goccy/go-yaml decodes anchors/aliases into a DAG of shared slice pointers
// rather than copying them, so Unmarshal-ing the fixture below is cheap
// (microseconds), but Loader.Load re-marshals the merged map before
// decoding it into *Config (see Load's doc) — and a plain yaml.Marshal of
// that DAG has to flatten every alias into literal text. Re-marshaling this
// 7-level/9-way fixture (9^7 ~ 4.8M leaf elements) takes several seconds and
// produces an ~85MB intermediate []byte from a ~250-byte config file.
//
// Load must not hang or exhaust memory during boot on a malformed/malicious
// config file: marshalMergedBounded's timeout (maxConfigMarshalDuration,
// well under this fixture's real marshal time) turns that into a fast,
// clear failure instead. This asserts Load returns an error well within a
// generous outer bound, wrapping errConfigMarshalTimeout.
func TestLoader_YAMLAnchorAmplification_FailsFastNotHangs(t *testing.T) {
	// Deliberately NOT t.Parallel(): Load's schema-violation warning path
	// (checkSchema/logSchemaViolations) writes through the package-global
	// slog.Default(), which TestLoader_UnknownKey_Warns temporarily swaps
	// for a capture buffer for the duration of ITS test body. Running
	// serially guarantees this test's Load call (and its background
	// goroutine, awaited below) completes before any parallel test group
	// is released, so it can never race with that logger swap.
	dir := t.TempDir()
	path := filepath.Join(dir, "evil.yaml")
	evil := `
logging:
  level: info
a: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
`
	if err := os.WriteFile(path, []byte(evil), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Load(path)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, errConfigMarshalTimeout) {
			t.Fatalf("Load error = %v, want wrapping errConfigMarshalTimeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load did not return within 5s — YAML anchor/alias amplification DoS regression (bounded timeout itself failed to fire)")
	}
}

// TestLoader_ReferenceConfigHasNoSpuriousAnchors guards against the exact
// failure mode an earlier fix attempt (goccy/go-yaml's WithSmartAnchor)
// introduced: its pointer-identity sharing detection produced FALSE
// POSITIVES on ordinary zero-value fields (Go's runtime returns the same
// address for unrelated empty-slice allocations), fabricating spurious
// anchors that corrupted a config with ZERO real YAML anchors in it. Any
// config with no anchors/aliases at all — the overwhelming common case —
// must always load cleanly.
func TestLoader_ReferenceConfigHasNoSpuriousAnchors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.yaml")
	plain := `
logging:
  level: info
server:
  issuer: https://issuer.example.com
identity:
  backend: memory
`
	if err := os.WriteFile(path, []byte(plain), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load of an anchor-free config failed: %v", err)
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

// fakeSecretResolver is a deterministic in-memory SecretResolver for tests:
// no network, no external SaaS. Resolve counts calls so a test can prove a
// leaf was (or was not) visited by the walker.
type fakeSecretResolver struct {
	provider string
	values   map[string]string
	calls    int
}

func (f *fakeSecretResolver) Provider() string { return f.provider }

func (f *fakeSecretResolver) Resolve(_ context.Context, path string) (string, error) {
	f.calls++
	v, ok := f.values[path]
	if !ok {
		return "", errors.New("fake resolver: unknown path " + path)
	}
	return v, nil
}

// TestResolveSecretReferences_ResolvesInsideSlice covers the []any recursion
// fix: a secret:// ref nested inside a list element (audit webhook
// subscriptions) MUST resolve. Without the fix the walker skipped slices and
// the reference shipped to YAML unmarshal verbatim, breaking the feature.
func TestResolveSecretReferences_ResolvesInsideSlice(t *testing.T) {
	r := &fakeSecretResolver{provider: "test", values: map[string]string{"whsec-siem": "RESOLVED-SIEM"}}
	m := map[string]any{
		"audit": map[string]any{
			"webhook": map[string]any{
				"subscriptions": []any{
					map[string]any{
						"name":           "siem",
						"url":            "https://siem.internal/audit",
						"signing_secret": "secret://test/whsec-siem",
					},
				},
			},
		},
	}
	if err := ResolveSecretReferences(context.Background(), m, map[string]SecretResolver{"test": r}); err != nil {
		t.Fatalf("ResolveSecretReferences: %v", err)
	}
	subs := m["audit"].(map[string]any)["webhook"].(map[string]any)["subscriptions"].([]any)
	got := subs[0].(map[string]any)["signing_secret"]
	if got != "RESOLVED-SIEM" {
		t.Fatalf("in-slice signing_secret = %v, want RESOLVED-SIEM", got)
	}
}

// TestResolveSecretReferences_HeadersMapInsideSlice proves the walker recurses
// map -> slice -> map -> map leaf (a header value carrying a secret:// ref
// inside a list element).
func TestResolveSecretReferences_HeadersMapInsideSlice(t *testing.T) {
	r := &fakeSecretResolver{provider: "test", values: map[string]string{"tok": "Bearer XYZ"}}
	m := map[string]any{
		"subscriptions": []any{
			map[string]any{
				"headers": map[string]any{"Authorization": "secret://test/tok"},
			},
		},
	}
	if err := ResolveSecretReferences(context.Background(), m, map[string]SecretResolver{"test": r}); err != nil {
		t.Fatalf("ResolveSecretReferences: %v", err)
	}
	hdrs := m["subscriptions"].([]any)[0].(map[string]any)["headers"].(map[string]any)
	if hdrs["Authorization"] != "Bearer XYZ" {
		t.Fatalf("in-slice header = %v, want Bearer XYZ", hdrs["Authorization"])
	}
}

// TestResolveSecretReferences_NoBehaviorChangeForExistingShapes locks the
// invariant that the []any addition changes nothing for the shapes that
// already worked: map-leaf secrets still resolve; plain (non-secret) strings,
// plain string slices, and non-string scalars are left byte-for-byte
// untouched. resolveMap touches ALL config, so this is the regression guard.
func TestResolveSecretReferences_NoBehaviorChangeForExistingShapes(t *testing.T) {
	r := &fakeSecretResolver{provider: "test", values: map[string]string{"db": "postgres://real"}}
	m := map[string]any{
		"postgres": map[string]any{"dsn": "secret://test/db"}, // map-leaf secret (pre-existing path)
		"server":   map[string]any{"listen": ":9090"},         // plain string, no ref
		"clients": []any{ // plain string slice must be untouched
			map[string]any{
				"id":            "web",
				"redirect_uris": []any{"https://a.example/cb", "https://b.example/cb"},
			},
		},
		"metrics": map[string]any{"enabled": true, "port": 9000}, // non-string scalars
	}
	if err := ResolveSecretReferences(context.Background(), m, map[string]SecretResolver{"test": r}); err != nil {
		t.Fatalf("ResolveSecretReferences: %v", err)
	}
	if got := m["postgres"].(map[string]any)["dsn"]; got != "postgres://real" {
		t.Fatalf("map-leaf secret = %v, want postgres://real", got)
	}
	if got := m["server"].(map[string]any)["listen"]; got != ":9090" {
		t.Fatalf("plain string mutated: %v", got)
	}
	uris := m["clients"].([]any)[0].(map[string]any)["redirect_uris"].([]any)
	if uris[0] != "https://a.example/cb" || uris[1] != "https://b.example/cb" {
		t.Fatalf("plain string slice mutated: %v", uris)
	}
	if r.calls != 1 {
		t.Fatalf("resolver called %d times, want 1 (only the single secret leaf)", r.calls)
	}
}

// TestLoad_AuditWebhookSubscriptions proves the subscriptions[] list decodes
// through the real loader path (merge -> yaml -> strict decode) into the typed
// AuditWebhookSubscription slice, including the event_types list and per-entry
// timeout / headers / retry.
func TestLoad_AuditWebhookSubscriptions(t *testing.T) {
	src := &stubSource{name: "test", data: map[string]any{
		"audit": map[string]any{
			"enabled": true,
			"webhook": map[string]any{
				"enabled": true,
				"subscriptions": []any{
					map[string]any{
						"name":           "siem",
						"url":            "https://siem.internal/audit",
						"event_types":    []any{"login", "admin_*"},
						"timeout":        "3s",
						"headers":        map[string]any{"X-Key": "v"},
						"signing_secret": "shh",
						"retry":          map[string]any{"max_attempts": 5},
					},
				},
			},
		},
	}}

	cfg, err := NewLoader(src).Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	subs := cfg.Audit.Webhook.Subscriptions
	if len(subs) != 1 {
		t.Fatalf("subscriptions len=%d want 1", len(subs))
	}
	s := subs[0]
	if s.Name != "siem" || s.URL != "https://siem.internal/audit" {
		t.Fatalf("name/url = %q/%q", s.Name, s.URL)
	}
	if len(s.EventTypes) != 2 || s.EventTypes[0] != "login" || s.EventTypes[1] != "admin_*" {
		t.Fatalf("event_types = %v want [login admin_*]", s.EventTypes)
	}
	if s.Timeout != 3*time.Second {
		t.Fatalf("timeout = %v want 3s", s.Timeout)
	}
	if s.Headers["X-Key"] != "v" {
		t.Fatalf("headers = %v", s.Headers)
	}
	if s.SigningSecret != "shh" {
		t.Fatalf("signing_secret = %q", s.SigningSecret)
	}
	if s.Retry.MaxAttempts != 5 {
		t.Fatalf("retry.max_attempts = %d want 5", s.Retry.MaxAttempts)
	}
}
