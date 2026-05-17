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
	// Verify that a populated Security block contributes three
	// sso.Option entries (body limit + rate limit + CORS) to
	// ServerOptions's output.
	p := writeTemp(t, "sec.yaml", securityYAML)
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	opts := cfg.ServerOptions()
	// Baseline (issuer / base_url / session_ttl / token_ttl) is 4
	// — plus the 3 security options = 7. Just a sanity floor.
	if len(opts) < 7 {
		t.Errorf("ServerOptions returned %d opts, want >= 7 (baseline + 3 security)", len(opts))
	}
}

func TestSecurityConfig_EmptyBlockSkipsAllThree(t *testing.T) {
	// Absent security: block → no middleware options emitted.
	p := writeTemp(t, "no-sec.yaml", "server: {issuer: t, listen: :8080}\n")
	cfg, _ := LoadFromSources(context.Background(), NewFileSource(p))
	opts := cfg.ServerOptions()
	if len(opts) > 5 {
		t.Errorf("got %d opts; expected baseline-only (no security middleware)", len(opts))
	}
}
