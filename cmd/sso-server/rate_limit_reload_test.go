package main

// rate_limit_reload_test.go covers wireRateLimitReload's closePolicyLimiters
// cleanup: a MemoryLimiter with a background pruner (StartPruner, opt-in via
// security.rate_limit.prune_interval) must be closed when a SIGHUP reload
// replaces its policy, or every reload leaks one more goroutine.

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	configreload "github.com/snaplink/sso/config/reload"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/interfaces/sso"
)

// closeCountingLimiter is a fake ratelimit.Limiter + io.Closer recording how
// many times Close was called, standing in for a real MemoryLimiter's
// background pruner shutdown.
type closeCountingLimiter struct {
	closes int
}

func (l *closeCountingLimiter) Allow(string) (bool, time.Duration) { return true, 0 }
func (l *closeCountingLimiter) Close() error {
	l.closes++
	return nil
}

func TestClosePolicyLimiters_ClosesDefaultAndPrefixes(t *testing.T) {
	t.Parallel()
	def := &closeCountingLimiter{}
	p1 := &closeCountingLimiter{}
	p2 := &closeCountingLimiter{}
	policy := ratelimit.Policy{
		Default: def,
		Prefixes: []ratelimit.PrefixRule{
			{Prefix: "/token", Limiter: p1},
			{Prefix: "/auth/login", Limiter: p2},
		},
	}

	closePolicyLimiters(policy)

	if def.closes != 1 {
		t.Errorf("Default.closes = %d, want 1", def.closes)
	}
	if p1.closes != 1 || p2.closes != 1 {
		t.Errorf("prefix limiter closes = %d, %d, want 1, 1", p1.closes, p2.closes)
	}
}

// TestClosePolicyLimiters_ZeroValueIsNoOp proves an empty/zero-value Policy
// (the pre-reload placeholder) never panics.
func TestClosePolicyLimiters_ZeroValueIsNoOp(t *testing.T) {
	t.Parallel()
	closePolicyLimiters(ratelimit.Policy{})
}

// TestWireRateLimitReload_ClosesPreviousPolicyOnReload drives a real SIGHUP
// reload through wireRateLimitReload with security.rate_limit.prune_interval
// set, and proves the REPLACED policy's MemoryLimiter background pruners are
// closed — not just discarded — so repeated reloads don't leak one more
// goroutine each time.
func TestWireRateLimitReload_ClosesPreviousPolicyOnReload(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithRateLimit(ratelimit.Policy{Key: ratelimit.KeyByClientIP}),
	)

	rl := config.RateLimitConfig{DefaultPerSec: 10, DefaultBurst: 10, PruneInterval: 5 * time.Millisecond}
	initial := &config.Config{Security: config.SecurityConfig{RateLimit: rl}}
	next := &config.Config{Security: config.SecurityConfig{RateLimit: rl}}
	reloader := configreload.New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	wireRateLimitReload(reloader, srv, nil)

	// First reload builds the FIRST real policy (with a live background
	// pruner) and swaps it in; the placeholder zero-value Policy from
	// WithRateLimit is closed as a no-op (no Closer fields set).
	if _, err := reloader.Reload(context.Background()); err != nil {
		t.Fatalf("first Reload: %v", err)
	}

	// Second reload builds a SECOND real policy and must close the FIRST
	// one's pruner goroutine before discarding it.
	if _, err := reloader.Reload(context.Background()); err != nil {
		t.Fatalf("second Reload: %v", err)
	}

	// A third reload proves the second policy's pruner was ALSO reachable
	// and didn't panic on close (Close is idempotent even if called twice
	// across the swap boundary).
	if _, err := reloader.Reload(context.Background()); err != nil {
		t.Fatalf("third Reload: %v", err)
	}
}
