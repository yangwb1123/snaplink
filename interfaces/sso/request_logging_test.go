package sso_test

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/metrics"
)

// accessLogRecord is one captured Info() call. Fields are the
// key/value pairs passed to the logger, in order.
type accessLogRecord struct {
	msg    string
	fields []any
}

func (r accessLogRecord) fieldValue(key string) (any, bool) {
	for i := 0; i+1 < len(r.fields); i += 2 {
		if k, ok := r.fields[i].(string); ok && k == key {
			return r.fields[i+1], true
		}
	}
	return nil, false
}

func (r accessLogRecord) hasKey(key string) bool {
	for i := 0; i < len(r.fields); i += 2 {
		if k, ok := r.fields[i].(string); ok && k == key {
			return true
		}
	}
	return false
}

// capturingInfoLogger records every Info() call — a real spi.Logger
// implementation, per repo convention (no mocking library). The
// always-on access log is the only Info path these tests drive.
type capturingInfoLogger struct {
	mu      sync.Mutex
	records []accessLogRecord
}

func (l *capturingInfoLogger) Info(msg string, keysAndValues ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, accessLogRecord{msg: msg, fields: keysAndValues})
}
func (l *capturingInfoLogger) Error(string, ...any) {}
func (l *capturingInfoLogger) Debug(string, ...any) {}

// accessRecords returns the captured "access" records in order.
func (l *capturingInfoLogger) accessRecords() []accessLogRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []accessLogRecord
	for _, r := range l.records {
		if r.msg == "access" {
			out = append(out, r)
		}
	}
	return out
}

// newAccessLogTestServer builds a minimal real Server (memory client
// store, client_credentials grant) wired with WithAccessLogging(policy)
// so a real /token round trip can be driven through the actual middleware
// chain (buildMiddlewareChain), not a unit call to the middleware alone.
func newAccessLogTestServer(t *testing.T, policy sso.BodyLogPolicy, opts ...sso.Option) (*httptest.Server, *capturingInfoLogger) {
	t.Helper()
	logger := &capturingInfoLogger{}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "rl-client", Secret: "rl-secret", Active: true,
		TokenStrategy: "jwt",
	})
	srv := sso.NewServer(append([]sso.Option{
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithLogger(logger),
		sso.WithAccessLogging(policy),
	}, opts...)...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, logger
}

// tokenRequestBody drives a real client_credentials /token round trip so
// the middleware chain sees both a real request body and a real response
// body.
func tokenRequestBody(t *testing.T, hs *httptest.Server) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"rl-client"},
		"client_secret": {"rl-secret"},
	}
	resp, err := hs.Client().Post(hs.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	_ = resp.Body.Close()
}

// TestWithAccessLogging_ExactlyOneRecordPerRequest pins the always-on
// contract: one INFO "access" record per request with the fixed
// low-cardinality field set, regardless of body policy.
func TestWithAccessLogging_ExactlyOneRecordPerRequest(t *testing.T) {
	hs, logger := newAccessLogTestServer(t, sso.BodyLogPolicy{})
	tokenRequestBody(t, hs)

	records := logger.accessRecords()
	if len(records) != 1 {
		t.Fatalf("expected exactly one access record per request, got %d", len(records))
	}
	for _, key := range []string{"method", "path", "status", "duration_ms", "client_ip", "request_id", "trace_id"} {
		if _, ok := records[0].fieldValue(key); !ok {
			t.Errorf("access record missing fixed field %q (fields: %v)", key, records[0].fields)
		}
	}
	if v, _ := records[0].fieldValue("method"); v != "POST" {
		t.Errorf("method = %v, want POST", v)
	}
	if v, _ := records[0].fieldValue("path"); v != "/token" {
		t.Errorf("path = %v, want /token", v)
	}
	if v, _ := records[0].fieldValue("status"); v != 200 {
		t.Errorf("status = %v, want 200", v)
	}
	if v, _ := records[0].fieldValue("duration_ms"); v == 0 {
		t.Error("duration_ms missing or zero")
	}
}

// TestWithAccessLogging_ZeroValuePolicy_NeverCapturesBodies is the
// credential-safety regression: the zero-value policy (the default) never
// emits request_body/response_body keys, so credentials are structurally
// impossible to log.
func TestWithAccessLogging_ZeroValuePolicy_NeverCapturesBodies(t *testing.T) {
	hs, logger := newAccessLogTestServer(t, sso.BodyLogPolicy{})
	tokenRequestBody(t, hs)

	records := logger.accessRecords()
	if len(records) != 1 {
		t.Fatalf("expected one access record, got %d", len(records))
	}
	if records[0].hasKey("request_body") {
		t.Error("zero-value policy: \"request_body\" key must be absent")
	}
	if records[0].hasKey("response_body") {
		t.Error("zero-value policy: \"response_body\" key must be absent")
	}
}

// TestWithAccessLogging_PolicyAllowsBodies_CapturesAndRedacts proves the
// policy-gated capture path through the real chain: an allowlisted path
// with an explicit sample rate captures bodies, and the redaction engine
// rewrites credential-shaped values (client_secret) before they reach the
// log record.
func TestWithAccessLogging_PolicyAllowsBodies_CapturesAndRedacts(t *testing.T) {
	policy := sso.BodyLogPolicy{
		Paths:        []string{"/token"},
		SampleRate:   1.0,
		MaxBodyBytes: 4096,
	}
	hs, logger := newAccessLogTestServer(t, policy)
	tokenRequestBody(t, hs)

	records := logger.accessRecords()
	if len(records) != 1 {
		t.Fatalf("expected one access record, got %d", len(records))
	}
	reqBody, ok := records[0].fieldValue("request_body")
	if !ok {
		t.Fatal("allowlisted path with sample_rate=1: expected request_body, got none")
	}
	if strings.Contains(reqBody.(string), "rl-secret") {
		t.Error("request_body leaked the client_secret value")
	}
	// url.Values.Encode() percent-encodes the literal, so decode the
	// captured form and assert the VALUE redacted to exactly [redacted].
	vals, err := url.ParseQuery(reqBody.(string))
	if err != nil {
		t.Fatalf("captured request_body is not form-encoded: %v", err)
	}
	if got := vals.Get("client_secret"); got != "[redacted]" {
		t.Errorf("client_secret redacted to %q, want exactly %q", got, "[redacted]")
	}
	if _, ok := records[0].fieldValue("response_body"); !ok {
		t.Error("allowlisted path with sample_rate=1: expected response_body, got none")
	}
}

// TestWithAccessLogging_NonAllowlistedPath_NeverCapturesBodies pins the
// allowlist gate: a path outside Paths stays body-free even with an
// explicit sample rate.
func TestWithAccessLogging_NonAllowlistedPath_NeverCapturesBodies(t *testing.T) {
	policy := sso.BodyLogPolicy{
		Paths:      []string{"/other"},
		SampleRate: 1.0,
	}
	hs, logger := newAccessLogTestServer(t, policy)
	tokenRequestBody(t, hs)

	records := logger.accessRecords()
	if len(records) != 1 {
		t.Fatalf("expected one access record, got %d", len(records))
	}
	if records[0].hasKey("request_body") || records[0].hasKey("response_body") {
		t.Error("non-allowlisted path must never capture bodies")
	}
}

// TestWithAccessLogging_QueryCredentialsNeverInPath pins the structural
// credential impossibility: a query string carrying code/token values
// never appears in the path field (path is r.URL.Path only), and the raw
// query values appear in NO access-log field.
func TestWithAccessLogging_QueryCredentialsNeverInPath(t *testing.T) {
	hs, logger := newAccessLogTestServer(t, sso.BodyLogPolicy{})
	// Discovery is a real GET route; the query is the hostile payload.
	resp, err := hs.Client().Get(hs.URL + "/.well-known/openid-configuration?code=secret-auth-code&token=secret-access-token")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	_ = resp.Body.Close()

	records := logger.accessRecords()
	if len(records) != 1 {
		t.Fatalf("expected one access record, got %d", len(records))
	}
	if v, _ := records[0].fieldValue("path"); v != "/.well-known/openid-configuration" {
		t.Errorf("path = %v, want /.well-known/openid-configuration (query must be excluded)", v)
	}
	for _, secret := range []string{"secret-auth-code", "secret-access-token"} {
		for i, f := range records[0].fields {
			if s, ok := f.(string); ok && strings.Contains(s, secret) {
				t.Errorf("query credential %q leaked into access field %d (%v)", secret, i, records[0].fields)
			}
		}
	}
}

// TestWithAccessLogging_ProbePathsExempt pins the probe exemption: /livez,
// /readyz, and /metrics are served by buildProbeMux OUTSIDE the middleware
// chain, so they produce no access record while a real API route does.
func TestWithAccessLogging_ProbePathsExempt(t *testing.T) {
	hs, logger := newAccessLogTestServer(t, sso.BodyLogPolicy{},
		sso.WithMetrics(metrics.New()),
	)
	for _, path := range []string{"/livez", "/readyz", "/metrics"} {
		resp, err := hs.Client().Get(hs.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("GET %s: unexpected status %d", path, resp.StatusCode)
		}
	}
	tokenRequestBody(t, hs)

	records := logger.accessRecords()
	if len(records) != 1 {
		t.Fatalf("expected exactly ONE access record (for /token only; probes exempt), got %d", len(records))
	}
	if v, _ := records[0].fieldValue("path"); v != "/token" {
		t.Errorf("the single access record must be the /token request, got path=%v", v)
	}
}

// TestWithRequestLogging_DeprecatedAliasStillInstallsAccessLog pins the
// compatibility surface: the deprecated name installs the same always-on
// access logger, and BodyLogPolicy{AllowAllPaths: true} reproduces the old
// logBodies=true semantics (bodies captured on every path).
func TestWithRequestLogging_DeprecatedAliasStillInstallsAccessLog(t *testing.T) {
	logger := &capturingInfoLogger{}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "rl-client", Secret: "rl-secret", Active: true,
		TokenStrategy: "jwt",
	})
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithLogger(logger),
		sso.WithRequestLogging(sso.BodyLogPolicy{AllowAllPaths: true, SampleRate: 1.0}),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	tokenRequestBody(t, hs)

	records := logger.accessRecords()
	if len(records) != 1 {
		t.Fatalf("expected one access record, got %d", len(records))
	}
	if v, _ := records[0].fieldValue("path"); v != "/token" {
		t.Errorf("path = %v, want /token", v)
	}
	if !records[0].hasKey("request_body") {
		t.Error("AllowAllPaths with sample_rate=1: expected request_body on every path")
	}
}
