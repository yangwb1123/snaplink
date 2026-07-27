package sso_test

// rate_limit_hotreload_test.go covers Server.SetRateLimitPolicy — the live
// rate-limit swap config/reload uses to apply a security.rate_limit.* SIGHUP
// change without a restart. Proves the swap actually reaches the
// already-built middleware chain (ratelimit.DynamicMiddleware reading a
// ratelimit.PolicyStore fresh per request), not just that the Policy struct
// field changed.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// rateLimitTestRequest drives a discovery request through the full
// middleware chain (rate limiting included) and returns the status code.
func rateLimitTestRequest(h http.Handler) int {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestSetRateLimitPolicy_LiveSwapTakesEffectImmediately proves the core
// claim: a policy swapped in AFTER Handler() was already built changes
// behavior on the VERY NEXT request — no restart, no re-Mount.
func TestSetRateLimitPolicy_LiveSwapTakesEffectImmediately(t *testing.T) {
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithRateLimit(ratelimit.Policy{
			Default: ratelimit.NewMemoryLimiter(1, 1), // burst of 1: second request in the same instant is rejected
		}),
	)
	h := srv.Handler()

	if code := rateLimitTestRequest(h); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", code)
	}
	if code := rateLimitTestRequest(h); code != http.StatusTooManyRequests {
		t.Fatalf("second request (burst exhausted) = %d, want 429", code)
	}

	// Swap in a much looser policy — same Handler(), same middleware chain,
	// no restart.
	if !srv.SetRateLimitPolicy(ratelimit.Policy{
		Default: ratelimit.NewMemoryLimiter(1000, 1000),
	}) {
		t.Fatal("SetRateLimitPolicy returned false, want true (rate limiting was enabled at boot)")
	}

	for i := 0; i < 5; i++ {
		if code := rateLimitTestRequest(h); code != http.StatusOK {
			t.Fatalf("request %d after policy swap = %d, want 200 (new looser policy should apply immediately)", i, code)
		}
	}
}

// TestSetRateLimitPolicy_NotEnabledAtBoot_ReturnsFalse proves the
// documented limitation: rate limiting can't be turned ON after boot —
// only the numbers inside an already-enabled policy can change live.
func TestSetRateLimitPolicy_NotEnabledAtBoot_ReturnsFalse(t *testing.T) {
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		// No WithRateLimit.
	)
	_ = srv.Handler() // build the chain, same as a real boot

	if srv.SetRateLimitPolicy(ratelimit.Policy{Default: ratelimit.NewMemoryLimiter(1, 1)}) {
		t.Fatal("SetRateLimitPolicy returned true, want false (rate limiting was never enabled at boot)")
	}
}
