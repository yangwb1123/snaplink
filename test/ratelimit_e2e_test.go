package ssotest

// End-to-end rate-limit integration — wires a real sso.Server with
// WithRateLimit, drives real HTTP through it, asserts that:
//   * /auth/login is throttled per-IP after burst exhausted
//   * /health (default bucket) is NOT throttled by the login-specific rule
//   * 429 responses carry the Retry-After header
//   * /metrics is NEVER rate-limited (scrapers don't get blocked)

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ratelimit"
)

// buildRateLimitHarness builds a server with a tight policy: tight
// /auth/login limiter (rate=1/s, burst=1 — second attempt blocked
// immediately), loose default (1000/s, burst=1000 — effectively no
// limit). Plus metrics so we can verify the 429s show up.
func buildRateLimitHarness(t *testing.T) (*httptest.Server, *metrics.Metrics) {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("rl-test"))
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    "rl-app",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	pwAuth := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "s3cret" {
				return &sso.AuthResult{UserID: "alice"}, nil
			}
			return nil, errors.New("bad creds")
		}),
	)
	m := metrics.New()
	policy := ratelimit.Policy{
		Default: ratelimit.NewMemoryLimiter(1000, 1000),
		Prefixes: []ratelimit.PrefixRule{
			{Prefix: "/auth/login", Limiter: ratelimit.NewMemoryLimiter(1, 1)},
		},
		// httptest reuses the same RemoteAddr across calls, so the
		// default per-IP keying naturally yields ONE bucket per test.
	}

	srv := sso.NewServer(
		sso.WithIssuer("rl-test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(permissions.NewMemoryProvider()),
		sso.WithMetrics(m),
		sso.WithRateLimit(policy),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, m
}

func postLoginRL(t *testing.T, srv *httptest.Server, password string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "rl-app",
		"credential": map[string]string{"username": "alice", "password": password},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	return resp
}

func TestRateLimitE2E_LoginBlockedAfterBurst(t *testing.T) {
	srv, _ := buildRateLimitHarness(t)

	// First attempt — within burst, may succeed or fail-creds, both
	// fine; bucket is now empty.
	resp := postLoginRL(t, srv, "s3cret")
	resp.Body.Close()

	// Second attempt — bucket empty, expect 429.
	resp = postLoginRL(t, srv, "s3cret")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("2nd login status = %d, want 429 body=%s", resp.StatusCode, raw)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("Retry-After header missing on 429")
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "rate_limited" {
		t.Errorf("error code = %q, want rate_limited", body["error"])
	}
}

func TestRateLimitE2E_HealthNotBlockedByLoginPolicy(t *testing.T) {
	srv, _ := buildRateLimitHarness(t)

	// Exhaust the /auth/login bucket.
	postLoginRL(t, srv, "wrong").Body.Close()
	postLoginRL(t, srv, "wrong").Body.Close()

	// /health uses the default (loose) bucket — must still pass.
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health = %d, want 200 (loose bucket)", resp.StatusCode)
	}
}

func TestRateLimitE2E_MetricsNeverRateLimited(t *testing.T) {
	srv, _ := buildRateLimitHarness(t)

	// Exhaust the /auth/login bucket aggressively.
	for range 10 {
		postLoginRL(t, srv, "wrong").Body.Close()
	}

	// /metrics must NEVER 429 — Prometheus scrapers depend on it
	// being available exactly when the system is under attack.
	for range 5 {
		resp, err := http.Get(srv.URL + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/metrics status = %d (rate-limited?!)", resp.StatusCode)
		}
	}
}

func TestRateLimitE2E_429sCountedAs4xxInMetrics(t *testing.T) {
	srv, _ := buildRateLimitHarness(t)

	// Generate a 429 deterministically.
	postLoginRL(t, srv, "wrong").Body.Close()
	resp := postLoginRL(t, srv, "wrong")
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 2nd POST, got %d", resp.StatusCode)
	}

	// Scrape /metrics; should see a POST 4xx in the request counter.
	mResp, _ := http.Get(srv.URL + "/metrics")
	body, _ := io.ReadAll(mResp.Body)
	mResp.Body.Close()
	if !bytes.Contains(body, []byte(`sso_http_requests_total{method="POST",status_class="4xx"}`)) {
		t.Errorf("429s not visible in HTTP counter; scrape:\n%s", body)
	}
}
