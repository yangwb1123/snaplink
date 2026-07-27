package sso_test

// client_registration_ratelimit_test.go proves checkClientRegistrationRateLimit
// (quota.go) — the narrow, IP-keyed rate limit on POST /register (RFC 7591 DCR)
// closing the gap AGENTS.md's rate-limiting review flagged: an unauthenticated
// (or IAT-shared, effectively public) registration endpoint with no throttle of
// its own beyond whatever coarse, OFF-BY-DEFAULT global security.rate_limit
// policy an operator may or may not have wired.
//
// Unlike rootcov_flow_test.go's rcovPostJSON (a real httptest.Server listener,
// so every request arrives from 127.0.0.1), these tests build requests
// directly and drive them through srv.Handler() — the only way to give
// different calls distinct RemoteAddr values and so prove the limiter's
// per-IP isolation, mirroring rate_limit_hotreload_test.go's approach for the
// global limiter.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// crlRegisterBody is the minimal RFC 7591 metadata an open-registration
// request needs — the same shape quota_test.go's dcrRegisterBody uses,
// minus tenant_id (open registration drops it; see registrationTenant).
func crlRegisterBody(name string) map[string]any {
	return map[string]any{
		"client_name":   name,
		"redirect_uris": []string{"https://crl.example.com/cb"},
	}
}

// crlNewServer wires an open-registration DCR policy (no initial access
// token required, so the test can focus purely on the rate limit) with an
// explicit client-registration limiter.
func crlNewServer(t *testing.T, limiter ratelimit.Limiter) http.Handler {
	t.Helper()
	srv := sso.NewServer(
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true}),
		sso.WithClientRegistrationRateLimit(limiter),
	)
	return srv.Handler()
}

// crlDoRegister drives one POST /register through h as if it originated from
// fromIP, and returns the status, decoded JSON body, and response headers.
func crlDoRegister(t *testing.T, h http.Handler, fromIP string, body map[string]any) (int, map[string]any, http.Header) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = fromIP + ":54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out, rec.Header()
}

// TestClientRegistrationRateLimit_TriggersAfterBurst proves the limit
// actually bites: with burst=2 (and a per-second rate too small to refill
// mid-test), the 3rd request from the same IP is rejected 429 with the
// standard rate_limited body, a Retry-After header, and no-store cache
// headers (this is a credential-shaped endpoint — AGENTS.md "Credential
// Endpoints" — so the rejection must get the same treatment as a success).
func TestClientRegistrationRateLimit_TriggersAfterBurst(t *testing.T) {
	t.Parallel()
	h := crlNewServer(t, ratelimit.NewMemoryLimiter(0.0001, 2))

	for i := 0; i < 2; i++ {
		code, out, _ := crlDoRegister(t, h, "203.0.113.5", crlRegisterBody("burst-client"))
		if code != http.StatusCreated {
			t.Fatalf("request %d = %d body=%v, want 201", i+1, code, out)
		}
	}

	code, out, hdr := crlDoRegister(t, h, "203.0.113.5", crlRegisterBody("burst-client"))
	if code != http.StatusTooManyRequests {
		t.Fatalf("3rd request from same IP = %d body=%v, want 429", code, out)
	}
	if out["error"] != ratelimit.ErrRateLimited {
		t.Fatalf("error = %v, want %s", out["error"], ratelimit.ErrRateLimited)
	}
	if hdr.Get("Retry-After") == "" {
		t.Fatal("429 response missing Retry-After header")
	}
	if got := hdr.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := hdr.Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
}

// TestClientRegistrationRateLimit_DifferentIPUnaffected proves there is no
// cross-contamination between buckets: IP A exhausting its burst must not
// affect IP B's independent bucket.
func TestClientRegistrationRateLimit_DifferentIPUnaffected(t *testing.T) {
	t.Parallel()
	h := crlNewServer(t, ratelimit.NewMemoryLimiter(0.0001, 1))

	if code, out, _ := crlDoRegister(t, h, "203.0.113.10", crlRegisterBody("ip-a-1")); code != http.StatusCreated {
		t.Fatalf("IP A first request = %d body=%v, want 201", code, out)
	}
	if code, out, _ := crlDoRegister(t, h, "203.0.113.10", crlRegisterBody("ip-a-2")); code != http.StatusTooManyRequests {
		t.Fatalf("IP A second request = %d body=%v, want 429 (burst exhausted)", code, out)
	}

	// A different source IP must get its own fresh bucket, unaffected by A's
	// exhausted one.
	if code, out, _ := crlDoRegister(t, h, "198.51.100.20", crlRegisterBody("ip-b-1")); code != http.StatusCreated {
		t.Fatalf("IP B request = %d body=%v, want 201 (must not share IP A's exhausted bucket)", code, out)
	}
	// And IP A must still be blocked — proves the isolation runs both ways,
	// not just that B got lucky with a shared/reset bucket.
	if code, out, _ := crlDoRegister(t, h, "203.0.113.10", crlRegisterBody("ip-a-3")); code != http.StatusTooManyRequests {
		t.Fatalf("IP A third request = %d body=%v, want 429 (still exhausted; B's traffic must not refill A's bucket)", code, out)
	}
}

// TestClientRegistrationRateLimit_ResetsAfterWindow proves the bucket
// actually refills: after the reported Retry-After elapses, a request that
// previously would have been rejected succeeds again.
func TestClientRegistrationRateLimit_ResetsAfterWindow(t *testing.T) {
	t.Parallel()
	// 1 token every 8 seconds, burst=1. The window is deliberately large
	// relative to a single request's worst-case latency: DCR mints +
	// bcrypt-hashes a registration_access_token on every call, and under
	// -race with many other t.Parallel() subtests contending for CPU, a
	// single bcrypt hash has been observed to take over a second — a
	// tight (sub-second or ~1s) window makes the "still exhausted"
	// assertion below flaky (confirmed by a prior version of this test).
	// Recovery is polled below (not a single fixed-duration sleep) for the
	// same reason: never assume any one request's latency.
	h := crlNewServer(t, ratelimit.NewMemoryLimiter(1.0/8, 1))

	if code, out, _ := crlDoRegister(t, h, "203.0.113.77", crlRegisterBody("reset-1")); code != http.StatusCreated {
		t.Fatalf("first request = %d body=%v, want 201", code, out)
	}
	code, out, hdr := crlDoRegister(t, h, "203.0.113.77", crlRegisterBody("reset-2"))
	if code != http.StatusTooManyRequests {
		t.Fatalf("second request (burst exhausted) = %d body=%v, want 429", code, out)
	}
	if hdr.Get("Retry-After") == "" {
		t.Fatal("429 response missing Retry-After header")
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		code, out, _ := crlDoRegister(t, h, "203.0.113.77", crlRegisterBody("reset-3"))
		if code == http.StatusCreated {
			return // bucket refilled — the window actually resets
		}
		if code != http.StatusTooManyRequests {
			t.Fatalf("unexpected status while polling for reset: %d body=%v", code, out)
		}
		if time.Now().After(deadline) {
			t.Fatal("bucket never refilled within 15s of the 8s window elapsing")
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// TestClientRegistrationRateLimit_DefaultOnWhenUnconfigured proves the
// central design claim: NewServer seeds a conservative built-in limiter
// (5/min, burst 5) with ZERO operator opt-in, unlike every other rate
// limiter in this codebase which stays off until explicitly wired.
func TestClientRegistrationRateLimit_DefaultOnWhenUnconfigured(t *testing.T) {
	t.Parallel()
	srv := sso.NewServer(
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true}),
		// No WithClientRegistrationRateLimit call at all.
	)
	h := srv.Handler()

	// 20 rapid calls against a burst-of-5 default is comfortably more than
	// can succeed however the exact refill timing plays out under load;
	// asserting "at least one 429 shows up" (rather than pinning it to
	// exactly the 6th call) avoids the same request-latency-vs-refill-rate
	// flakiness TestClientRegistrationRateLimit_ResetsAfterWindow's history
	// ran into with a tighter assertion.
	var sawRateLimited bool
	for i := 0; i < 20; i++ {
		code, out, _ := crlDoRegister(t, h, "203.0.113.200", crlRegisterBody("default-probe"))
		if code == http.StatusTooManyRequests {
			sawRateLimited = true
			break
		}
		if code != http.StatusCreated {
			t.Fatalf("request %d = %d body=%v, want 201 or 429", i+1, code, out)
		}
	}
	if !sawRateLimited {
		t.Fatal("20 rapid registrations against the DEFAULT limiter never hit 429 — built-in burst cap is not being enforced")
	}
}

// TestClientRegistrationRateLimit_DisabledViaNil proves the escape hatch:
// WithClientRegistrationRateLimit(nil) fully disables the guard, mirroring
// WithSelfServiceSignupRateLimiter's nil-disables convention (options_passwd.go).
func TestClientRegistrationRateLimit_DisabledViaNil(t *testing.T) {
	t.Parallel()
	h := crlNewServer(t, nil)
	for i := 0; i < 10; i++ {
		if code, out, _ := crlDoRegister(t, h, "203.0.113.201", crlRegisterBody("disabled-probe")); code != http.StatusCreated {
			t.Fatalf("request %d with limiter explicitly disabled = %d body=%v, want 201 always", i+1, code, out)
		}
	}
}
