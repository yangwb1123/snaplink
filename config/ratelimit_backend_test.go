package config

import (
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/interfaces/ratelimit"
)

// TestRateLimitConfig_ToPolicy_SQLiteBackendHonored proves
// RateLimitConfig.toPolicy() actually builds the cluster-shared SQLite
// limiter when security.rate_limit.backend=sqlite, instead of silently
// downgrading to an in-process MemoryLimiter. Before the fix, toPolicy
// ignored Backend entirely and always returned a MemoryLimiter — an
// embedder calling config.ServerOptions() directly (the documented,
// signature-only translation from *Config to []sso.Option) would get a
// per-replica-only rate limiter with zero indication that the configured
// "sqlite" backend was never actually wired.
func TestRateLimitConfig_ToPolicy_SQLiteBackendHonored(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "rl.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	r := &RateLimitConfig{
		Enabled:       true,
		Backend:       "sqlite",
		SQLite:        RateLimitSQLiteConfig{DSN: dsn},
		DefaultPerSec: 1,
		DefaultBurst:  10,
		Prefixes: []RateLimitPrefixConfig{
			{Prefix: "/auth/login", PerSec: 0.5, Burst: 5},
		},
	}
	policy := r.toPolicy()
	if _, ok := policy.Default.(*ratelimit.SQLiteLimiter); !ok {
		t.Fatalf("toPolicy() with backend=sqlite built Default of type %T, want *ratelimit.SQLiteLimiter — "+
			"the configured cluster-shared backend was silently downgraded to an in-process limiter", policy.Default)
	}
	if len(policy.Prefixes) != 1 {
		t.Fatalf("got %d prefix rules, want 1", len(policy.Prefixes))
	}
	if _, ok := policy.Prefixes[0].Limiter.(*ratelimit.SQLiteLimiter); !ok {
		t.Errorf("prefix limiter type = %T, want *ratelimit.SQLiteLimiter", policy.Prefixes[0].Limiter)
	}
}

// TestRateLimitConfig_ToPolicy_MemoryBackendDefault locks in the
// unchanged default: "" (unset) still builds an in-process MemoryLimiter.
func TestRateLimitConfig_ToPolicy_MemoryBackendDefault(t *testing.T) {
	t.Parallel()
	r := &RateLimitConfig{Enabled: true, DefaultPerSec: 1, DefaultBurst: 10}
	policy := r.toPolicy()
	if _, ok := policy.Default.(*ratelimit.MemoryLimiter); !ok {
		t.Fatalf("toPolicy() with no backend built Default of type %T, want *ratelimit.MemoryLimiter", policy.Default)
	}
}

// TestRateLimitConfig_ToPolicy_MissingDSNFallsBackToMemory proves a
// misconfigured sqlite backend (no DSN) degrades to a working, if
// non-cluster-shared, limiter rather than a nil Default that silently
// disables rate limiting altogether.
func TestRateLimitConfig_ToPolicy_MissingDSNFallsBackToMemory(t *testing.T) {
	t.Parallel()
	r := &RateLimitConfig{Enabled: true, Backend: "sqlite", DefaultPerSec: 1, DefaultBurst: 10}
	policy := r.toPolicy()
	if _, ok := policy.Default.(*ratelimit.MemoryLimiter); !ok {
		t.Fatalf("toPolicy() with backend=sqlite and no DSN built Default of type %T, want the fallback *ratelimit.MemoryLimiter", policy.Default)
	}
}

// TestRateLimitConfig_ToPolicy_UnsupportedBackendFallsBackToMemory proves
// an unrecognized backend (e.g. "redis", which this package cannot build a
// client for) degrades to memory instead of silently producing a policy
// that LOOKS like every other backend's build but enforces nothing the
// operator actually asked for.
func TestRateLimitConfig_ToPolicy_UnsupportedBackendFallsBackToMemory(t *testing.T) {
	t.Parallel()
	r := &RateLimitConfig{Enabled: true, Backend: "redis", DefaultPerSec: 1, DefaultBurst: 10}
	policy := r.toPolicy()
	if _, ok := policy.Default.(*ratelimit.MemoryLimiter); !ok {
		t.Fatalf("toPolicy() with backend=redis built Default of type %T, want the fallback *ratelimit.MemoryLimiter", policy.Default)
	}
}
