package ssotest

// Assembly-level access-log tests: wire a real sso.Server with the full
// chain (tracing + trusted proxies + rate limit + access log), drive real
// HTTP, and assert on the INFO "access" records. This is the integration
// counterpart to the middleware unit tests — the chain order (AccessLogger
// inside trustedProxies, outside ratelimit) is exactly what ships in
// cmd/sso-server.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/metrics"
)

// accessLogLine is one captured Info() call.
type accessLogLine struct {
	msg    string
	fields []any
}

func (l accessLogLine) field(key string) (any, bool) {
	for i := 0; i+1 < len(l.fields); i += 2 {
		if k, ok := l.fields[i].(string); ok && k == key {
			return l.fields[i+1], true
		}
	}
	return nil, false
}

// infoCapture is a real spi.Logger recording every Info() call.
type infoCapture struct {
	mu      sync.Mutex
	records []accessLogLine
}

func (l *infoCapture) Info(msg string, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, accessLogLine{msg: msg, fields: kv})
}
func (l *infoCapture) Error(string, ...any) {}
func (l *infoCapture) Debug(string, ...any) {}

func (l *infoCapture) accessRecords() []accessLogLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []accessLogLine
	for _, r := range l.records {
		if r.msg == "access" {
			out = append(out, r)
		}
	}
	return out
}

// newAccessLogHarness builds the full production-shaped chain. trusted
// proxies treats the loopback test peer as a trusted edge so X-Forwarded-For
// is honored and the access log records the validated real client IP; the
// tight /auth/login limiter produces a 429 to prove the access logger sits
// outside rate limiting.
func newAccessLogHarness(t *testing.T) (*httptest.Server, *infoCapture) {
	t.Helper()
	logger := &infoCapture{}

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("access-log-test"))
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    "al-app",
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

	opts := []sso.Option{
		sso.WithIssuer("access-log-test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithLogger(logger),
		sso.WithTracingMiddleware(), // request_id/trace_id population
		sso.WithAccessLogging(sso.BodyLogPolicy{}),
		sso.WithMetrics(metrics.New()),
	}
	tp, err := sso.WithTrustedProxies([]string{"127.0.0.1/32"}, 1)
	if err != nil {
		t.Fatalf("WithTrustedProxies: %v", err)
	}
	opts = append(opts, tp)
	opts = append(opts, sso.WithRateLimit(ratelimit.Policy{
		Default: ratelimit.NewMemoryLimiter(1000, 1000),
		Prefixes: []ratelimit.PrefixRule{
			{Prefix: "/auth/login", Limiter: ratelimit.NewMemoryLimiter(1, 1)},
		},
	}))
	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, logger
}

// TestAccessLog_FullChainExactlyOneRecordPerRequest asserts the always-on
// contract end to end: fixed field set present, request_id/trace_id
// populated by the tracing middleware, client_ip = validated real IP under
// XFF spoofing (trusted-proxy gate), and path never carries the query.
func TestAccessLog_FullChainExactlyOneRecordPerRequest(t *testing.T) {
	hs, logger := newAccessLogHarness(t)

	req, err := http.NewRequest(http.MethodGet, hs.URL+"/.well-known/openid-configuration?code=spoofed-auth-code&token=spoofed-access-token", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.9") // untrusted hop -> real client
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	_ = resp.Body.Close()

	records := logger.accessRecords()
	if len(records) != 1 {
		t.Fatalf("expected exactly one access record per request, got %d", len(records))
	}
	rec := records[0]
	for _, key := range []string{"method", "path", "status", "duration_ms", "client_ip", "request_id", "trace_id"} {
		if _, ok := rec.field(key); !ok {
			t.Errorf("access record missing fixed field %q", key)
		}
	}
	if got, _ := rec.field("path"); got != "/.well-known/openid-configuration" {
		t.Errorf("path = %v, want path without query", got)
	}
	for _, secret := range []string{"spoofed-auth-code", "spoofed-access-token"} {
		for i, f := range rec.fields {
			if s, ok := f.(string); ok && strings.Contains(s, secret) {
				t.Errorf("query credential %q leaked into field %d", secret, i)
			}
		}
	}
	if got, _ := rec.field("client_ip"); got != "203.0.113.9" {
		t.Errorf("client_ip = %v, want validated 203.0.113.9 (XFF honored only via trusted proxy)", got)
	}
	if got, _ := rec.field("request_id"); got == "" {
		t.Error("request_id should be populated by the tracing middleware")
	}
	if got, _ := rec.field("trace_id"); got == "" {
		t.Error("trace_id should be populated by the tracing middleware")
	}
}

// TestAccessLog_RateLimitedRequestStillLogged asserts the slot decision:
// the access logger sits OUTSIDE rate limiting, so a 429 rejection leaves
// access evidence with the rejection status.
func TestAccessLog_RateLimitedRequestStillLogged(t *testing.T) {
	hs, logger := newAccessLogHarness(t)

	login := func() int {
		body := `{"provider":"password","client_id":"al-app","scope":["openid"],"credential":{"username":"alice","password":"s3cret"}}`
		resp, err := hs.Client().Post(hs.URL+"/auth/login", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST /auth/login: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if got := login(); got != http.StatusOK {
		t.Fatalf("first login: got %d, want 200", got)
	}
	if got := login(); got != http.StatusTooManyRequests {
		t.Fatalf("second login: got %d, want 429", got)
	}

	records := logger.accessRecords()
	if len(records) != 2 {
		t.Fatalf("expected two access records (one per request), got %d", len(records))
	}
	if got, _ := records[0].field("status"); got != http.StatusOK {
		t.Errorf("first login status = %v, want 200", got)
	}
	if got, _ := records[1].field("status"); got != http.StatusTooManyRequests {
		t.Errorf("rate-limited login status = %v, want 429 (access log outside the limiter)", got)
	}
}

// TestAccessLog_ProbePathsExempt asserts the probe mux exemption holds in
// the full chain: /livez /readyz /metrics produce no access records.
func TestAccessLog_ProbePathsExempt(t *testing.T) {
	hs, logger := newAccessLogHarness(t)
	for _, path := range []string{"/livez", "/readyz", "/metrics"} {
		resp, err := hs.Client().Get(hs.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
	}
	if got := len(logger.accessRecords()); got != 0 {
		t.Fatalf("probe paths must produce no access records, got %d", got)
	}
}
