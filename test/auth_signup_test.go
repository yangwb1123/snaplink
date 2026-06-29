package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/spi"
)

func newSignupHarness(t *testing.T, enabled bool) (*httptest.Server, *defaultimpl.MemoryUserProvider, *defaultimpl.MemoryPasswordCredentialStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	pw := defaultimpl.NewMemoryPasswordCredentialStore()
	opts := []sso.Option{
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithUserProvider(users),
		sso.WithPasswordCredentialStore(pw),
	}
	if enabled {
		opts = append(opts, sso.WithSelfServiceSignup())
	}
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)
	return hs, users, pw
}

func postSignup(t *testing.T, srv *httptest.Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/register", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestSignup_HappyPath(t *testing.T) {
	srv, users, pw := newSignupHarness(t, true)
	ctx := context.Background()

	code, body := postSignup(t, srv, map[string]any{"username": "newuser", "password": "pw12345678", "email": "new@example.com"})
	if code != http.StatusCreated || body["user_id"] != "newuser" {
		t.Fatalf("signup = %d %v, want 201 user_id=newuser", code, body)
	}
	u, err := users.GetByID(ctx, "newuser")
	if err != nil || u == nil || u.Email != "new@example.com" {
		t.Errorf("created user = %v, %v", u, err)
	}
	if err := pw.VerifyPassword(ctx, "newuser", "pw12345678"); err != nil {
		t.Errorf("password not set for new user: %v", err)
	}
}

func TestSignup_DuplicateRejected(t *testing.T) {
	srv, users, _ := newSignupHarness(t, true)
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "taken", Email: "existing@example.com"})

	code, body := postSignup(t, srv, map[string]any{"username": "taken", "password": "pw12345678"})
	if code != http.StatusConflict || body["error"] != "account_exists" {
		t.Fatalf("duplicate = %d %v, want 409 account_exists", code, body)
	}
	// The existing account must be untouched (not overwritten).
	if u, _ := users.GetByID(context.Background(), "taken"); u == nil || u.Email != "existing@example.com" {
		t.Errorf("existing account was overwritten: %v", u)
	}
}

func TestSignup_RejectsMissingFields(t *testing.T) {
	srv, _, _ := newSignupHarness(t, true)
	if c, _ := postSignup(t, srv, map[string]any{"username": "x"}); c != http.StatusBadRequest {
		t.Errorf("missing password = %d, want 400", c)
	}
	if c, _ := postSignup(t, srv, map[string]any{"password": "x"}); c != http.StatusBadRequest {
		t.Errorf("missing username = %d, want 400", c)
	}
}

func TestSignup_NotMountedWhenDisabled(t *testing.T) {
	srv, _, _ := newSignupHarness(t, false)
	if c, _ := postSignup(t, srv, map[string]any{"username": "x", "password": "y"}); c != http.StatusNotFound {
		t.Errorf("disabled = %d, want 404 (unmounted)", c)
	}
}

// newSignupWithOpts builds a signup-enabled server with any extra options.
// Useful for wiring rate limiters or registration gates in isolation.
func newSignupWithOpts(t *testing.T, extra ...sso.Option) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	pw := defaultimpl.NewMemoryPasswordCredentialStore()
	opts := append([]sso.Option{
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithUserProvider(users),
		sso.WithPasswordCredentialStore(pw),
		sso.WithSelfServiceSignup(),
	}, extra...)
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)
	return hs
}

// ---------- nil-userProvider guard in rejectUnverifiedEmail ----------

// TestSignupRequireVerification_NilProviderPassthrough guards the nil-provider
// branch of rejectUnverifiedEmail: when signupRequireVerification=true but no
// UserProvider is wired, the gate cannot check verification status and must
// pass through (allow login). Without this guard the gate would panic.
func TestSignupRequireVerification_NilProviderPassthrough(t *testing.T) {
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("nil-prov-test"))
	sessions := defaultimpl.NewMemorySessionManager()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "app", AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "pw" {
				return &sso.AuthResult{UserID: "alice"}, nil
			}
			return nil, errors.New("bad creds")
		}),
	)
	// No WithUserProvider — s.userProvider == nil.
	server := sso.NewServer(
		sso.WithSignupRequireVerification(true),
		sso.WithSessionManager(sessions),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	hs := httptest.NewServer(server.Handler())
	defer hs.Close()

	body, _ := json.Marshal(map[string]any{
		"provider": "password", "client_id": "app",
		"credential": map[string]string{"username": "alice", "password": "pw"},
	})
	resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d want 200; nil userProvider must pass through: body=%v", resp.StatusCode, out)
	}
	if _, ok := out["access_token"]; !ok {
		t.Errorf("access_token missing: body=%v", out)
	}
}

// ---------- per-IP signup rate limiter ----------

// stubSignupRateLimiter implements selfservicecore.RateLimiter for testing.
type stubSignupRateLimiter struct {
	retryAfter time.Duration // zero means no Retry-After header
}

func (s *stubSignupRateLimiter) Allow(_ string) (bool, time.Duration) {
	return false, s.retryAfter
}

// TestSignupRateLimit_Returns429WithRetryAfterCeiling verifies:
//   - A rejected signup returns 429 rate_limited.
//   - Sub-second retryAfter is rounded UP (ceiling): RFC 7231 treats
//     Retry-After: 0 as "retry immediately", so 500ms must become 1.
//   - A retryAfter of 0 suppresses the header entirely.
func TestSignupRateLimit_Returns429WithRetryAfterCeiling(t *testing.T) {
	cases := []struct {
		retryAfter     time.Duration
		wantHeader     string
		wantHeaderSet  bool
	}{
		{500 * time.Millisecond, "1", true},
		{time.Second, "1", true},
		{1001 * time.Millisecond, "2", true},
		{0, "", false},
	}
	for _, tc := range cases {
		lim := &stubSignupRateLimiter{retryAfter: tc.retryAfter}
		srv := newSignupWithOpts(t, sso.WithSelfServiceSignupRateLimiter(lim))

		raw, _ := json.Marshal(map[string]any{"username": "u", "password": "pw12345678"})
		resp, err := http.Post(srv.URL+"/auth/register", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("retryAfter=%v: request: %v", tc.retryAfter, err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("retryAfter=%v: status = %d, want 429", tc.retryAfter, resp.StatusCode)
		}
		got := resp.Header.Get("Retry-After")
		if tc.wantHeaderSet {
			if got != tc.wantHeader {
				t.Errorf("retryAfter=%v: Retry-After = %q, want %q", tc.retryAfter, got, tc.wantHeader)
			}
			if _, err := strconv.Atoi(got); err != nil {
				t.Errorf("retryAfter=%v: Retry-After is not an integer: %q", tc.retryAfter, got)
			}
		} else if got != "" {
			t.Errorf("retryAfter=%v: unexpected Retry-After = %q, want absent", tc.retryAfter, got)
		}
	}
}

// ---------- registration gate receives clean IP (not host:port) ----------

// stubRegistrationGate records the IP passed to CheckRegistration so the
// test can assert it is a clean IP without the TCP port suffix.
type stubRegistrationGate struct {
	lastIP string
}

func (g *stubRegistrationGate) CheckRegistration(_ context.Context, _, _, ip string) error {
	g.lastIP = ip
	return nil
}

var _ spi.RegistrationGate = (*stubRegistrationGate)(nil)

// TestRegistrationGates_ReceivesCleanIP proves runRegistrationGates uses
// middleware.RealClientIP (port-stripped) not ctx.Request().RemoteAddr
// (which includes host:port). Without TrustedProxies middleware, RealClientIP
// falls back to RemoteAddr stripped of port — so the gate must receive a
// parseable IP address with no colon suffix.
func TestRegistrationGates_ReceivesCleanIP(t *testing.T) {
	gate := &stubRegistrationGate{}
	srv := newSignupWithOpts(t, sso.WithRegistrationGates(gate))

	_, _ = postSignup(t, srv, map[string]any{"username": "iptest", "password": "pw12345678"})

	if net.ParseIP(gate.lastIP) == nil {
		t.Errorf("gate received non-IP value %q; RealClientIP must strip port", gate.lastIP)
	}
}
