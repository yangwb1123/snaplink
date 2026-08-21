package reload

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

func baseConfig() *config.Config {
	return &config.Config{
		Server:  config.ServerConfig{Issuer: "https://sso.example.com"},
		Logging: config.LoggingConfig{Level: "info"},
	}
}

func TestReload_AppliesLogLevelAndCallsHook(t *testing.T) {
	var gotLevel string
	initial := baseConfig()
	next := baseConfig()
	next.Logging.Level = "debug"

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, func(l string) { gotLevel = l })

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if gotLevel != "debug" {
		t.Errorf("setLogLevel hook got %q, want debug", gotLevel)
	}
	if len(res.Applied) != 1 {
		t.Fatalf("Applied = %v, want exactly one entry", res.Applied)
	}
	if res.Applied[0] != `logging.level: "info" -> "debug"` {
		t.Errorf("Applied[0] = %q", res.Applied[0])
	}
	if len(res.Ignored) != 0 {
		t.Errorf("Ignored = %v, want none", res.Ignored)
	}
	if got := r.Current().Logging.Level; got != "debug" {
		t.Errorf("Current().Logging.Level = %q, want debug", got)
	}
}

func TestReload_IgnoresNonSafeFieldsAndLeavesThemUntouched(t *testing.T) {
	initial := baseConfig()
	next := baseConfig()
	next.Server.Issuer = "https://changed.example.com" // NOT in safeReloadPaths

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 0 {
		t.Errorf("Applied = %v, want none (server.issuer requires a restart)", res.Applied)
	}
	found := false
	for _, p := range res.Ignored {
		if p == "/server/issuer" {
			found = true
		}
	}
	if !found {
		t.Errorf("Ignored = %v, want it to contain /server/issuer", res.Ignored)
	}
	if got := r.Current().Server.Issuer; got != "https://sso.example.com" {
		t.Errorf("Current().Server.Issuer = %q, want the ORIGINAL value untouched (restart required)", got)
	}
}

func TestReload_LogLevelWithoutHookIsReportedAsIgnored(t *testing.T) {
	// A caller that never wires setLogLevel gets an honest "this needs a
	// restart" answer rather than a false claim of having applied it live.
	initial := baseConfig()
	next := baseConfig()
	next.Logging.Level = "error"

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 0 {
		t.Errorf("Applied = %v, want none (no setLogLevel hook wired)", res.Applied)
	}
	found := false
	for _, p := range res.Ignored {
		if p == "/logging/level" {
			found = true
		}
	}
	if !found {
		t.Errorf("Ignored = %v, want it to contain /logging/level", res.Ignored)
	}
	if got := r.Current().Logging.Level; got != "info" {
		t.Errorf("Current().Logging.Level = %q, want untouched", got)
	}
}

func TestReload_NoChangesProducesEmptyResult(t *testing.T) {
	initial := baseConfig()
	r := New(initial, func(context.Context) (*config.Config, error) { return baseConfig(), nil }, nil)

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if res.Changed() {
		t.Errorf("Result = %+v, want no changes", res)
	}
}

func TestReload_SourceErrorLeavesStateUntouched(t *testing.T) {
	initial := baseConfig()
	boom := errors.New("boom")
	r := New(initial, func(context.Context) (*config.Config, error) { return nil, boom }, nil)

	_, err := r.Reload(context.Background())
	if err == nil {
		t.Fatal("expected an error from a failing reload source")
	}
	if got := r.Current().Logging.Level; got != "info" {
		t.Errorf("Current() must be untouched after a failed reload, got level %q", got)
	}
}

func TestReload_NilSourceReturnsError(t *testing.T) {
	r := New(baseConfig(), nil, nil)
	if _, err := r.Reload(context.Background()); err == nil {
		t.Fatal("expected an error when no reload source is configured")
	}
}

func TestReload_AppliesRateLimitAndCallsHook(t *testing.T) {
	var gotCfg config.RateLimitConfig
	initial := baseConfig()
	initial.Security.RateLimit.DefaultPerSec = 1
	next := baseConfig()
	next.Security.RateLimit.DefaultPerSec = 5
	next.Security.RateLimit.DefaultBurst = 10

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	r.SetRateLimitHook(func(cfg config.RateLimitConfig) error {
		gotCfg = cfg
		return nil
	})

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if gotCfg.DefaultPerSec != 5 || gotCfg.DefaultBurst != 10 {
		t.Errorf("rate limit hook got %+v, want DefaultPerSec=5 DefaultBurst=10", gotCfg)
	}
	if len(res.Applied) != 1 || res.Applied[0] != "security.rate_limit: policy rebuilt" {
		t.Fatalf("Applied = %v, want exactly one rate_limit entry", res.Applied)
	}
	if len(res.Ignored) != 0 {
		t.Errorf("Ignored = %v, want none", res.Ignored)
	}
	if got := r.Current().Security.RateLimit.DefaultPerSec; got != 5 {
		t.Errorf("Current().Security.RateLimit.DefaultPerSec = %v, want 5", got)
	}
}

func TestReload_RateLimitMultipleLeafChangesApplyOnce(t *testing.T) {
	// Changing BOTH DefaultPerSec and DefaultBurst in one reload must call
	// the hook exactly once (one rebuilt Policy), not once per changed leaf.
	var calls int
	initial := baseConfig()
	next := baseConfig()
	next.Security.RateLimit.DefaultPerSec = 5
	next.Security.RateLimit.DefaultBurst = 10

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	r.SetRateLimitHook(func(config.RateLimitConfig) error {
		calls++
		return nil
	})

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if calls != 1 {
		t.Errorf("rate limit hook called %d times, want exactly 1", calls)
	}
	if len(res.Applied) != 1 {
		t.Errorf("Applied = %v, want exactly one entry", res.Applied)
	}
}

func TestReload_RateLimitWithoutHookIsReportedAsIgnored(t *testing.T) {
	initial := baseConfig()
	next := baseConfig()
	next.Security.RateLimit.DefaultPerSec = 5

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 0 {
		t.Errorf("Applied = %v, want none (no rate-limit hook wired)", res.Applied)
	}
	found := false
	for _, p := range res.Ignored {
		if p == "/security/rate_limit" {
			found = true
		}
	}
	if !found {
		t.Errorf("Ignored = %v, want it to contain /security/rate_limit", res.Ignored)
	}
	if got := r.Current().Security.RateLimit.DefaultPerSec; got != 0 {
		t.Errorf("Current().Security.RateLimit.DefaultPerSec = %v, want untouched", got)
	}
}

func TestReload_RateLimitHookErrorIsReportedAsIgnored(t *testing.T) {
	initial := baseConfig()
	next := baseConfig()
	next.Security.RateLimit.DefaultPerSec = 5

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	r.SetRateLimitHook(func(config.RateLimitConfig) error {
		return errors.New("bad backend")
	})

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 0 {
		t.Errorf("Applied = %v, want none (hook errored)", res.Applied)
	}
	if got := r.Current().Security.RateLimit.DefaultPerSec; got != 0 {
		t.Errorf("Current().Security.RateLimit.DefaultPerSec = %v, want untouched after a hook error", got)
	}
}

func TestReload_AppliesAdminAPIGateAndCallsHook(t *testing.T) {
	var got bool
	var called int
	initial := baseConfig()
	next := baseConfig()
	next.FeatureGates.AdminAPI = boolPtr(false)

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	r.SetAdminAPIGateHook(func(enabled bool) bool {
		called++
		got = enabled
		return true
	})

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if called != 1 {
		t.Fatalf("admin_api hook called %d times, want exactly 1", called)
	}
	if got != false {
		t.Errorf("admin_api hook got %v, want false", got)
	}
	if len(res.Applied) != 1 || res.Applied[0] != "feature_gates.admin_api: true -> false" {
		t.Fatalf("Applied = %v, want exactly one admin_api entry", res.Applied)
	}
	if len(res.Ignored) != 0 {
		t.Errorf("Ignored = %v, want none", res.Ignored)
	}
	if got := r.Current().FeatureGates.AdminAPI; got == nil || *got != false {
		t.Errorf("Current().FeatureGates.AdminAPI = %v, want false", got)
	}
}

func TestReload_AdminAPIGateWithoutHookIsReportedAsIgnored(t *testing.T) {
	initial := baseConfig()
	next := baseConfig()
	next.FeatureGates.AdminAPI = boolPtr(false)

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 0 {
		t.Errorf("Applied = %v, want none (no admin_api hook wired)", res.Applied)
	}
	if !containsPath(res.Ignored, "/feature_gates/admin_api") {
		t.Errorf("Ignored = %v, want it to contain /feature_gates/admin_api", res.Ignored)
	}
	if got := r.Current().FeatureGates.AdminAPI; got != nil {
		t.Errorf("Current().FeatureGates.AdminAPI = %v, want untouched (nil)", got)
	}
}

// TestReload_WebSPAGateHookReportingNoEffectIsIgnoredNotApplied proves the
// one asymmetry SetBrandingGateHook is subject to: a wired hook that itself
// reports false (Server.SetBrandingGateEnabled — no tenant store was ever
// wired at boot) must still surface as Ignored, not a false Applied. This
// is the "graceful, not a silent no-op that looks like it worked" case.
// The legacy /feature_gates/web_spa diff path is exercised too: the
// normalized config carries the value in FeatureGates.Branding either way.
func TestReload_WebSPAGateHookReportingNoEffectIsIgnored(t *testing.T) {
	initial := baseConfig()
	next := baseConfig()
	next.FeatureGates.Branding = boolPtr(false)

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	r.SetBrandingGateHook(func(bool) bool { return false }) // mirrors "no tenant store wired"

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 0 {
		t.Errorf("Applied = %v, want none (hook reported no effect)", res.Applied)
	}
	if !containsPath(res.Ignored, "/feature_gates/branding") {
		t.Errorf("Ignored = %v, want it to contain /feature_gates/branding", res.Ignored)
	}
	if got := r.Current().FeatureGates.Branding; got != nil {
		t.Errorf("Current().FeatureGates.Branding = %v, want untouched (nil)", got)
	}
}

// TestReload_LegacyWebSPAPathIsIgnoredNotUnknown proves the deprecated
// /feature_gates/web_spa diff path is still recognized (reported as Ignored
// when no hook is wired) rather than falling into the unknown-path bucket,
// so an operator who has not yet migrated their config keeps hot-reload
// diagnostics instead of a silent no-op.
func TestReload_LegacyWebSPAPathIsIgnoredNotUnknown(t *testing.T) {
	initial := baseConfig()
	next := baseConfig()
	next.FeatureGates.Branding = boolPtr(false)

	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if !containsPath(res.Ignored, "/feature_gates/branding") {
		t.Errorf("Ignored = %v, want it to contain /feature_gates/branding", res.Ignored)
	}
	if containsPath(res.Ignored, "/feature_gates/web_spa") {
		t.Errorf("Ignored = %v, must not contain legacy /feature_gates/web_spa (normalized away)", res.Ignored)
	}
}

func TestReload_RebuildsWebhookDeliveryPolicyOnly(t *testing.T) {
	initial := baseConfig()
	initial.Webhooks.Enabled = true
	next := baseConfig()
	next.Webhooks.Enabled = true
	next.Webhooks.DeliveryTimeout = 3
	next.Webhooks.Retry.InitialBackoff = 4
	next.Webhooks.DeadLetterCapacity = 99
	var got config.WebhooksConfig
	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	r.SetWebhooksHook(func(cfg config.WebhooksConfig) error {
		got = cfg
		return nil
	})

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 1 || res.Applied[0] != "webhooks: delivery policy generation replaced" {
		t.Fatalf("Applied = %v", res.Applied)
	}
	if !containsPath(res.Ignored, "/webhooks/dead_letter_capacity") {
		t.Fatalf("Ignored = %v, want dead-letter capacity restart boundary", res.Ignored)
	}
	if got.DeliveryTimeout != next.Webhooks.DeliveryTimeout || got.Retry != next.Webhooks.Retry {
		t.Fatalf("webhook hook received %+v, want %+v", got, next.Webhooks)
	}
	current := r.Current().Webhooks
	if current.DeliveryTimeout != next.Webhooks.DeliveryTimeout || current.Retry != next.Webhooks.Retry {
		t.Fatalf("Current.Webhooks = %+v, want delivery policy applied", current)
	}
	if current.DeadLetterCapacity != 0 {
		t.Fatalf("Current.DeadLetterCapacity = %d, want restart-required value untouched", current.DeadLetterCapacity)
	}
}

func TestReload_WebhookPolicyWithoutRuntimeIsIgnored(t *testing.T) {
	initial := baseConfig()
	next := baseConfig()
	next.Webhooks.Enabled = true
	next.Webhooks.DeliveryTimeout = 3
	r := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)

	res, err := r.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 0 || !containsPath(res.Ignored, "/webhooks") {
		t.Fatalf("Result = %+v, want ignored webhook policy", res)
	}
	if r.Current().Webhooks.DeliveryTimeout != 0 {
		t.Fatal("unwired webhook policy changed tracked config")
	}
}

func boolPtr(b bool) *bool { return &b }

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

func TestReload_ConcurrentReloadsAreSafe(t *testing.T) {
	initial := baseConfig()
	r := New(initial, func(context.Context) (*config.Config, error) { return baseConfig(), nil }, func(string) {})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Reload(context.Background())
			_ = r.Current()
		}()
	}
	wg.Wait()
}
