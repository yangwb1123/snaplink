package config

import (
	"context"
	"reflect"
	"testing"
	"time"
)

const securityYAML = `
server:
  issuer: t
  listen: :8080
security:
  body_limit:
    max_bytes: 1048576
  rate_limit:
    enabled: true
    default_per_sec: 1
    default_burst: 60
    prefixes:
      - prefix: /auth/login
        per_sec: 0.167
        burst: 10
      - prefix: /auth/send-code
        per_sec: 0.167
        burst: 10
  cors:
    enabled: true
    allowed_origins: ["https://app.example.com"]
    allowed_headers: ["Authorization", "X-Custom"]
    exposed_headers: ["X-Request-ID"]
    allow_credentials: true
    max_age: 1h
`

func TestSecurityConfig_Parses(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "sec.yaml", securityYAML)
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}

	if cfg.Security.BodyLimit.MaxBytes != 1<<20 {
		t.Errorf("body_limit.max_bytes = %d, want %d", cfg.Security.BodyLimit.MaxBytes, 1<<20)
	}
	if !cfg.Security.RateLimit.Enabled {
		t.Error("rate_limit.enabled should be true")
	}
	if cfg.Security.RateLimit.DefaultBurst != 60 {
		t.Errorf("default_burst = %d", cfg.Security.RateLimit.DefaultBurst)
	}
	if len(cfg.Security.RateLimit.Prefixes) != 2 {
		t.Fatalf("got %d prefix rules, want 2", len(cfg.Security.RateLimit.Prefixes))
	}
	if cfg.Security.RateLimit.Prefixes[0].Prefix != "/auth/login" {
		t.Errorf("prefix[0] = %q", cfg.Security.RateLimit.Prefixes[0].Prefix)
	}

	if !cfg.Security.CORS.Enabled {
		t.Error("cors.enabled should be true")
	}
	if !reflect.DeepEqual(cfg.Security.CORS.AllowedOrigins, []string{"https://app.example.com"}) {
		t.Errorf("allowed_origins = %v", cfg.Security.CORS.AllowedOrigins)
	}
	if cfg.Security.CORS.MaxAge != time.Hour {
		t.Errorf("max_age = %v", cfg.Security.CORS.MaxAge)
	}
}

func TestSecurityConfig_ServerOptionsWiresThree(t *testing.T) {
	t.Parallel()
	// Verify that a populated Security block contributes three
	// sso.Option entries (body limit + rate limit + CORS) to
	// ServerOptions's output.
	p := writeTemp(t, "sec.yaml", securityYAML)
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	opts := cfg.ServerOptions()
	// Baseline is WithIssuer + the always-on access log (default-on via
	// logging.access_log). With SecurityConfig populated we add WithBodyLimit
	// + WithRateLimit + WithCORS, so the total should be exactly 5.
	if len(opts) != 5 {
		t.Errorf("ServerOptions returned %d opts, want 5 (issuer + access log + 3 security)", len(opts))
	}
}

func TestSecurityConfig_EmptyBlockAppliesBodyLimitDefault(t *testing.T) {
	t.Parallel()
	// Absent security: block → rate-limit + CORS stay skipped, but the
	// conservative body-limit DEFAULT is now applied by applyDefaults
	// (secure-by-default: an omitted body_limit is bounded, not unbounded).
	// So WithIssuer + WithBodyLimit(default) = exactly 2 opts.
	p := writeTemp(t, "no-sec.yaml", "server: {issuer: t, listen: :8080}\n")
	cfg, _ := LoadFromSources(context.Background(), NewFileSource(p))
	if cfg.Security.BodyLimit.MaxBytes != DefaultBodyLimitBytes {
		t.Errorf("omitted body_limit normalized to %d, want default %d",
			cfg.Security.BodyLimit.MaxBytes, DefaultBodyLimitBytes)
	}
	opts := cfg.ServerOptions()
	// WithIssuer + the always-on access log + WithBodyLimit(default).
	if len(opts) != 3 {
		t.Errorf("got %d opts; expected exactly 3 (WithIssuer + access log + WithBodyLimit default)", len(opts))
	}
}

func TestSecurityConfig_NegativeBodyLimitIsUnlimited(t *testing.T) {
	t.Parallel()
	// max_bytes: -1 is the explicit unlimited escape hatch — normalized to
	// 0 so no WithBodyLimit is wired (just WithIssuer survives).
	p := writeTemp(t, "unlimited.yaml", "server: {issuer: t, listen: :8080}\nsecurity: {body_limit: {max_bytes: -1}}\n")
	cfg, _ := LoadFromSources(context.Background(), NewFileSource(p))
	if cfg.Security.BodyLimit.MaxBytes != 0 {
		t.Errorf("negative body_limit normalized to %d, want 0 (unlimited)", cfg.Security.BodyLimit.MaxBytes)
	}
	opts := cfg.ServerOptions()
	// WithIssuer + the always-on access log (body limit unwired).
	if len(opts) != 2 {
		t.Errorf("got %d opts; expected exactly 2 (WithIssuer + access log, body limit unwired)", len(opts))
	}
}

func TestSecurityConfig_RARCatalogCheck(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "rar-catalog.yaml", `server:
  issuer: t
  listen: :8080
security:
  body_limit:
    max_bytes: -1
  rar_catalog_check:
    enabled: true
`)
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	if !cfg.Security.RARCatalogCheck.Enabled {
		t.Fatal("rar_catalog_check.enabled should be true")
	}
	if got := len(cfg.ServerOptions()); got != 3 {
		t.Fatalf("ServerOptions returned %d opts, want issuer + access log + RAR catalog check", got)
	}
}
