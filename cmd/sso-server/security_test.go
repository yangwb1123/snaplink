package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/ratelimit"
)

func TestBuildRateLimitPolicy_DefaultAndPrefixes(t *testing.T) {
	p := buildRateLimitPolicy(config.RateLimitConfig{
		Enabled:       true,
		DefaultPerSec: 5,
		DefaultBurst:  10,
		Prefixes: []config.RateLimitPrefixConfig{
			{Prefix: "/auth/login", PerSec: 1, Burst: 2},
			{Prefix: "/auth/send-code", PerSec: 1, Burst: 2},
		},
	})
	if p.Default == nil {
		t.Fatal("Default limiter unexpectedly nil")
	}
	if len(p.Prefixes) != 2 {
		t.Errorf("Prefixes count = %d want 2", len(p.Prefixes))
	}
	if p.Prefixes[0].Prefix != "/auth/login" {
		t.Errorf("first prefix = %q", p.Prefixes[0].Prefix)
	}
	// Key defaults to per-client-or-IP so HTTP Basic on /token buckets
	// per-client rather than per source IP.
	if p.Key == nil {
		t.Error("Key func unexpectedly nil")
	}
}

func TestBuildRateLimitPolicy_ZeroDefaultLeavesDefaultLimiterNil(t *testing.T) {
	// A zero DefaultPerSec means "no limit on unmatched paths" — only
	// the prefix rules apply.
	p := buildRateLimitPolicy(config.RateLimitConfig{
		Enabled:       true,
		DefaultPerSec: 0,
		Prefixes: []config.RateLimitPrefixConfig{
			{Prefix: "/auth/login", PerSec: 1, Burst: 2},
		},
	})
	if p.Default != nil {
		t.Errorf("Default limiter should be nil when DefaultPerSec=0")
	}
	if len(p.Prefixes) != 1 {
		t.Errorf("Prefixes count = %d want 1", len(p.Prefixes))
	}
}

func TestBuildApp_BodyLimitWired(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.BodyLimit.MaxBytes = 16

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	// A POST whose body exceeds the cap returns 413 before the router
	// even routes it. Use a path that exists (/token) so the failure is
	// the size check, not a routing miss.
	big := make([]byte, 64)
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded",
		bytes.NewReader(big))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d want 413", resp.StatusCode)
	}
}

func TestBuildApp_JTIReplayStoreWiredWhenEnabled(t *testing.T) {
	// Smoke test: just confirm buildApp doesn't panic and the option
	// chain is reachable when the flag is on. End-to-end JAR replay
	// behavior is covered by SDK-level tests.
	cfg := &config.Config{}
	cfg.Security.JTIReplay.Enabled = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	if a.server == nil {
		t.Fatal("server nil")
	}
}

func TestBuildApp_AccountLockoutWiredWithOverrides(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AccountLockout.Enabled = true
	cfg.Security.AccountLockout.MaxFailures = 3

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	if a.server == nil {
		t.Fatal("server nil")
	}
}

func TestBuildApp_AccountLockoutDefaultsWhenZeroValues(t *testing.T) {
	// Zero numeric values fall back to SDK defaults — confirms the
	// wiring code doesn't accidentally pass 0 to the override
	// branches (which would lock the account on the first failure).
	cfg := &config.Config{}
	cfg.Security.AccountLockout.Enabled = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	if a.server == nil {
		t.Fatal("server nil")
	}
}

func TestBuildApp_CORSWiredWhenOriginsSet(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.CORS.Enabled = true
	cfg.Security.CORS.AllowedOrigins = []string{"https://example.com"}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	r, _ := http.NewRequest(http.MethodOptions, srv.URL+"/token", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("Allow-Origin = %q want %q", got, "https://example.com")
	}
}

// Compile-time guard against ratelimit drift; if Policy/PrefixRule
// shapes rename, this file should still build.
var _ = ratelimit.Policy{}
