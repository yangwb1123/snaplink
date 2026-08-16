package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// recordingLogger captures Info() calls — a real spi.Logger per repo
// convention. The access log is the only Info path in these tests.
type recordingLogger struct {
	mu      sync.Mutex
	records []accessLogRecord
}

type accessLogRecord struct {
	msg    string
	fields []any
}

func (l *recordingLogger) Info(msg string, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, accessLogRecord{msg: msg, fields: kv})
}
func (l *recordingLogger) Error(string, ...any) {}
func (l *recordingLogger) Debug(string, ...any) {}

func (l *recordingLogger) accessRecords() []accessLogRecord {
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

func (r accessLogRecord) field(key string) (any, bool) {
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

// accessLogChain builds the middleware around a handler and serves one
// request, returning the captured access records.
func accessLogChain(t *testing.T, policy BodyLogPolicy, next http.HandlerFunc, mutate func(*http.Request) *http.Request) (*recordingLogger, []accessLogRecord) {
	t.Helper()
	logger := &recordingLogger{}
	h := AccessLogger(logger, policy)(next)
	req := httptest.NewRequest("POST", "/token?code=abc123&token=xyz", strings.NewReader("grant_type=client_credentials&client_id=c&client_secret=s3cret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(core.HeaderRequestID, "req-42")
	req = req.WithContext(core.WithTraceID(req.Context(), "trace-1"))
	if mutate != nil {
		req = mutate(req)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return logger, logger.accessRecords()
}

func TestBodyLogPolicy_EnabledFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		policy BodyLogPolicy
		path   string
		want   bool
	}{
		{"zero-value-never", BodyLogPolicy{}, "/token", false},
		{"allowlist-hit", BodyLogPolicy{Paths: []string{"/token"}}, "/token", true},
		{"allowlist-miss", BodyLogPolicy{Paths: []string{"/token"}}, "/other", false},
		{"allow-all", BodyLogPolicy{AllowAllPaths: true}, "/anything", true},
		{"paths-beat-allow-all", BodyLogPolicy{Paths: []string{"/token"}, AllowAllPaths: true}, "/other", false},
		{"paths-beat-allow-all-hit", BodyLogPolicy{Paths: []string{"/token"}, AllowAllPaths: true}, "/token", true},
		{"exact-match-only", BodyLogPolicy{Paths: []string{"/token"}}, "/token/", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.EnabledFor(tc.path); got != tc.want {
				t.Fatalf("EnabledFor(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestAccessLogger_FixedFieldSet_ExactlyOneRecord(t *testing.T) {
	_, records := accessLogChain(t, BodyLogPolicy{}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}, nil)
	if len(records) != 1 {
		t.Fatalf("exactly one INFO access record per request, got %d", len(records))
	}
	for _, key := range []string{"method", "path", "status", "duration_ms", "client_ip", "request_id", "trace_id"} {
		if _, ok := records[0].field(key); !ok {
			t.Errorf("missing fixed field %q", key)
		}
	}
	if got, _ := records[0].field("status"); got != http.StatusCreated {
		t.Errorf("status = %v, want %d", got, http.StatusCreated)
	}
	if got, _ := records[0].field("request_id"); got != "req-42" {
		t.Errorf("request_id = %v, want req-42", got)
	}
	if got, _ := records[0].field("trace_id"); got != "trace-1" {
		t.Errorf("trace_id = %v, want trace-1", got)
	}
	if got, _ := records[0].field("duration_ms"); got == 0 {
		t.Error("duration_ms missing or zero")
	}
}

func TestAccessLogger_PathNeverContainsQuery(t *testing.T) {
	_, records := accessLogChain(t, BodyLogPolicy{}, func(http.ResponseWriter, *http.Request) {}, nil)
	if got, _ := records[0].field("path"); got != "/token" {
		t.Fatalf("path = %v, want /token (RawQuery must never be included)", got)
	}
}

func TestAccessLogger_QueryCredentialsAbsentFromAllFields(t *testing.T) {
	_, records := accessLogChain(t, BodyLogPolicy{}, func(http.ResponseWriter, *http.Request) {}, nil)
	for _, secret := range []string{"abc123", "xyz"} {
		for i, f := range records[0].fields {
			if s, ok := f.(string); ok && strings.Contains(s, secret) {
				t.Errorf("query credential %q leaked into field %d (%v)", secret, i, records[0].fields)
			}
		}
	}
}

func TestAccessLogger_DefaultStatus200(t *testing.T) {
	// Handler writes a body but never calls WriteHeader: net/http's
	// implicit 200 must be recorded.
	_, records := accessLogChain(t, BodyLogPolicy{}, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}, nil)
	if got, _ := records[0].field("status"); got != http.StatusOK {
		t.Errorf("status = %v, want 200", got)
	}
}

func TestAccessLogger_ZeroValuePolicy_NoBodyFields(t *testing.T) {
	_, records := accessLogChain(t, BodyLogPolicy{}, func(http.ResponseWriter, *http.Request) {}, nil)
	if records[0].hasKey("request_body") || records[0].hasKey("response_body") {
		t.Error("zero-value policy must never emit body fields")
	}
}

func TestAccessLogger_SampleRateZero_NeverCapturesEvenOnAllowlist(t *testing.T) {
	policy := BodyLogPolicy{Paths: []string{"/token"}, SampleRate: 0}
	_, records := accessLogChain(t, policy, func(http.ResponseWriter, *http.Request) {}, nil)
	if records[0].hasKey("request_body") || records[0].hasKey("response_body") {
		t.Error("sample_rate=0 must never capture bodies, even on an allowlisted path")
	}
}

func TestAccessLogger_SampleRateOne_CapturesAndRestoresBody(t *testing.T) {
	var seen string
	policy := BodyLogPolicy{Paths: []string{"/token"}, SampleRate: 1.0}
	_, records := accessLogChain(t, policy, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("handler body read: %v", err)
		}
		seen = string(b)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, nil)

	// Restore-before-forward: the handler must see the FULL original body,
	// identical to what the client sent (capture never consumes it).
	want := "grant_type=client_credentials&client_id=c&client_secret=s3cret"
	if seen != want {
		t.Errorf("handler saw body %q, want full original %q", seen, want)
	}
	if !records[0].hasKey("request_body") {
		t.Error("allowlist+sample_rate=1: expected request_body")
	}
	if !records[0].hasKey("response_body") {
		t.Error("allowlist+sample_rate=1: expected response_body")
	}
}

func TestAccessLogger_ResponseBodyCapped(t *testing.T) {
	policy := BodyLogPolicy{Paths: []string{"/token"}, SampleRate: 1.0, MaxBodyBytes: 16}
	_, records := accessLogChain(t, policy, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789abcdef0123456789")) // 28 bytes > cap 16
	}, nil)
	body, _ := records[0].field("response_body")
	if len(body.(string)) != 16 {
		t.Errorf("response_body captured %d bytes, want cap 16", len(body.(string)))
	}
	if body.(string) != "0123456789abcdef" {
		t.Errorf("response_body = %q, want first 16 bytes", body.(string))
	}
}

func TestAccessLogger_ClientIPTrustedProxyWinsOverForgedXFF(t *testing.T) {
	_, records := accessLogChain(t, BodyLogPolicy{}, func(http.ResponseWriter, *http.Request) {}, func(r *http.Request) *http.Request {
		r.RemoteAddr = "203.0.113.9:443"
		r.Header.Set("X-Forwarded-For", "10.0.0.7")
		return r.WithContext(peertrust.WithRequestInfo(r.Context(), peertrust.RequestInfo{
			ClientIP:                "203.0.113.9",
			ForwardedHeadersTrusted: false,
		}))
	})
	if got, _ := records[0].field("client_ip"); got != "203.0.113.9" {
		t.Errorf("client_ip = %v, want canonical trusted-proxy verdict 203.0.113.9", got)
	}
}

func TestAccessLogger_ClientIPLegacyFirstHopFallback(t *testing.T) {
	// No trust gate installed: X-Forwarded-For first hop wins (the
	// documented legacy contract), port stripped.
	_, records := accessLogChain(t, BodyLogPolicy{}, func(http.ResponseWriter, *http.Request) {}, func(r *http.Request) *http.Request {
		r.RemoteAddr = "10.0.0.1:80"
		r.Header.Set("X-Forwarded-For", "198.51.100.4, 10.0.0.9")
		return r
	})
	if got, _ := records[0].field("client_ip"); got != "198.51.100.4" {
		t.Errorf("client_ip = %v, want 198.51.100.4", got)
	}
}

func TestAccessLogger_EmptyFieldsWhenNoCorrelation(t *testing.T) {
	// request_id/trace_id are header/context reads: absent correlation
	// middleware => empty strings, fields still present (always emitted).
	logger := &recordingLogger{}
	h := AccessLogger(logger, BodyLogPolicy{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	records := logger.accessRecords()
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if got, _ := records[0].field("request_id"); got != "" {
		t.Errorf("request_id = %v, want empty", got)
	}
	if got, _ := records[0].field("trace_id"); got != "" {
		t.Errorf("trace_id = %v, want empty", got)
	}
}

func TestAccessLogger_Redaction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		contentType string
		body        string
		wantLeak    string // a raw secret value that must NOT appear
		wantRedact  string // a redacted marker that MUST appear
	}{
		{
			name:        "form-secret",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=alice&password=topsecret",
			wantLeak:    "topsecret",
			wantRedact:  "redacted",
		},
		{
			name:        "form-substring-heuristic",
			contentType: "application/x-www-form-urlencoded",
			body:        "my_mfa_code=123456",
			wantLeak:    "123456",
			wantRedact:  "redacted",
		},
		{
			name:        "json-nested",
			contentType: "application/json",
			body:        `{"data":{"password":"hunter2"},"keep":"ok"}`,
			wantLeak:    "hunter2",
			wantRedact:  "[redacted]",
		},
		{
			name:        "json-array-nested",
			contentType: "application/json",
			body:        `{"items":[{"client_secret":"s3cr3t"}],"ok":true}`,
			wantLeak:    "s3cr3t",
			wantRedact:  "[redacted]",
		},
		{
			name:        "raw-passthrough",
			contentType: "application/octet-stream",
			body:        "\x00\x01binary",
			wantLeak:    "",
			wantRedact:  "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactBody(tc.contentType, []byte(tc.body))
			if tc.wantLeak != "" && strings.Contains(got, tc.wantLeak) {
				t.Errorf("raw secret %q leaked into redacted body: %q", tc.wantLeak, got)
			}
			if tc.wantRedact != "" && !strings.Contains(got, tc.wantRedact) {
				t.Errorf("expected redaction marker %q in %q", tc.wantRedact, got)
			}
		})
	}
}

func TestAccessLogger_MalformedBodyPassesThroughRaw(t *testing.T) {
	// A malformed body for its declared content type must not be dropped
	// (debugging aid) and must not panic — the cap + allowlist still gate.
	if got := redactBody("application/json", []byte("{not-json")); got != "{not-json" {
		t.Errorf("malformed JSON = %q, want raw passthrough", got)
	}
	if got := redactBody("application/x-www-form-urlencoded", []byte("%zz%20")); !strings.Contains(got, "%zz") {
		t.Errorf("malformed form = %q, want raw passthrough", got)
	}
}

var _ spi.Logger = (*recordingLogger)(nil)
