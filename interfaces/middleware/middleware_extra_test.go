package middleware

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/tracing"
	"github.com/yangwb1123/snaplink/shared/core"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// fakeTokenIssuer is a real in-package core.TokenIssuer test double used to
// drive the Auth middleware down both its accept and reject branches. It is a
// test seam for the TokenIssuer SPI, not a mock of a repo concern — Auth only
// ever calls Validate, so Issue/Revoke are inert.
type fakeTokenIssuer struct {
	wantToken string // token value that validates successfully
	claims    *core.TokenClaims
	err       error // returned when the presented token != wantToken
}

func (f *fakeTokenIssuer) Issue(_ context.Context, _ *core.Subject, _ []string) (*core.Token, error) {
	return nil, errors.New("not used")
}

func (f *fakeTokenIssuer) Validate(_ context.Context, token string) (*core.TokenClaims, error) {
	if token == f.wantToken {
		return f.claims, nil
	}
	return nil, f.err
}

func (f *fakeTokenIssuer) Revoke(_ context.Context, _ string) error { return errors.New("not used") }

// captureLogger is a real spi.Logger test double recording the messages and
// key/value pairs the Logger middleware emits.
type captureLogger struct {
	msgs []string
	kvs  [][]any
}

func (l *captureLogger) Info(msg string, kv ...any) {
	l.msgs = append(l.msgs, msg)
	l.kvs = append(l.kvs, kv)
}
func (l *captureLogger) Error(msg string, _ ...any) { l.msgs = append(l.msgs, msg) }
func (l *captureLogger) Debug(msg string, _ ...any) { l.msgs = append(l.msgs, msg) }

// errBody extracts the {"error":"<code>"} value an OAuth/OIDC handler writes,
// without pulling in a JSON dependency for a single field.
func errBody(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	body := strings.TrimSpace(w.Body.String())
	const k = `"error":"`
	i := strings.Index(body, k)
	if i < 0 {
		return body
	}
	rest := body[i+len(k):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return rest
	}
	return rest[:j]
}

// --- Auth ---------------------------------------------------------------

func TestAuth_MissingHeader(t *testing.T) {
	t.Parallel()

	iss := &fakeTokenIssuer{wantToken: "good", claims: &core.TokenClaims{Subject: "s"}, err: errors.New("bad")}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	Auth(iss)(core.NewContext(w, r))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := errBody(t, w); got != core.ErrUnauthorized {
		t.Errorf("error = %q, want %q", got, core.ErrUnauthorized)
	}
}

func TestAuth_NonBearerScheme(t *testing.T) {
	t.Parallel()

	iss := &fakeTokenIssuer{wantToken: "good", err: errors.New("bad")}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set(core.HeaderAuthorization, "Basic dXNlcjpwYXNz")
	Auth(iss)(core.NewContext(w, r))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	// A non-Bearer scheme is treated as no credentials → unauthorized, NOT
	// invalid_token (which would imply a malformed-but-present bearer).
	if got := errBody(t, w); got != core.ErrUnauthorized {
		t.Errorf("error = %q, want %q", got, core.ErrUnauthorized)
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	t.Parallel()

	iss := &fakeTokenIssuer{wantToken: "good", err: errors.New("signature mismatch")}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set(core.HeaderAuthorization, core.BearerPrefix+"forged")
	Auth(iss)(core.NewContext(w, r))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := errBody(t, w); got != core.ErrInvalidToken {
		t.Errorf("error = %q, want %q", got, core.ErrInvalidToken)
	}
}

func TestAuth_ValidToken_PassesThrough(t *testing.T) {
	t.Parallel()

	iss := &fakeTokenIssuer{wantToken: "good", claims: &core.TokenClaims{Subject: "alice"}, err: errors.New("bad")}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set(core.HeaderAuthorization, core.BearerPrefix+"good")
	Auth(iss)(core.NewContext(w, r))

	// Auth is a pure gate: on success it writes nothing, leaving the recorder
	// at its zero (200) default with an empty body.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (untouched)", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body = %q, want empty on success", w.Body.String())
	}
}

// --- CORS ---------------------------------------------------------------

func TestCORS_AllowedOriginEcho(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://app.example.com")
	CORS([]string{"https://other.example.com", "https://app.example.com"})(core.NewContext(w, r))

	if got := w.Header().Get(core.HeaderAccessControlOrigin); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q, want the matched origin", got)
	}
	if got := w.Header().Get(core.HeaderAccessControlMethods); got != core.CORSAllowedMethods {
		t.Errorf("Allow-Methods = %q, want %q", got, core.CORSAllowedMethods)
	}
	if got := w.Header().Get(core.HeaderAccessControlHeaders); got != core.CORSAllowedHeaders {
		t.Errorf("Allow-Headers = %q, want %q", got, core.CORSAllowedHeaders)
	}
}

func TestCORS_DeniedOrigin_NoAllowOriginHeader(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	CORS([]string{"https://app.example.com"})(core.NewContext(w, r))

	// Origin not in allowlist and no wildcard → no Allow-Origin reflected.
	if got := w.Header().Get(core.HeaderAccessControlOrigin); got != "" {
		t.Errorf("Allow-Origin = %q, want empty for denied origin", got)
	}
	// Methods/Headers are still advertised (they are not origin-gated).
	if got := w.Header().Get(core.HeaderAccessControlMethods); got != core.CORSAllowedMethods {
		t.Errorf("Allow-Methods = %q, want %q", got, core.CORSAllowedMethods)
	}
}

func TestCORS_Wildcard(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://anything.example.com")
	CORS([]string{core.CORSAllowAllOrigin})(core.NewContext(w, r))

	if got := w.Header().Get(core.HeaderAccessControlOrigin); got != core.CORSAllowAllOrigin {
		t.Errorf("Allow-Origin = %q, want %q (wildcard)", got, core.CORSAllowAllOrigin)
	}
}

func TestCORS_PreflightShortCircuits(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/", nil)
	r.Header.Set("Origin", "https://app.example.com")
	CORS([]string{"https://app.example.com"})(core.NewContext(w, r))

	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", w.Code)
	}
	if got := w.Header().Get(core.HeaderAccessControlOrigin); got != "https://app.example.com" {
		t.Errorf("preflight Allow-Origin = %q, want the matched origin", got)
	}
}

func TestCORS_NoOriginHeader(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// No Origin header at all (same-origin request).
	CORS([]string{"https://app.example.com"})(core.NewContext(w, r))

	if got := w.Header().Get(core.HeaderAccessControlOrigin); got != "" {
		t.Errorf("Allow-Origin = %q, want empty when no Origin sent", got)
	}
}

// --- Logger -------------------------------------------------------------

func TestLogger_EmitsMethodAndPath(t *testing.T) {
	t.Parallel()

	lg := &captureLogger{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	Logger(lg)(core.NewContext(w, r))

	if len(lg.msgs) != 1 || lg.msgs[0] != "request" {
		t.Fatalf("messages = %v, want one %q", lg.msgs, "request")
	}
	kv := lg.kvs[0]
	got := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		got[kv[i].(string)] = kv[i+1]
	}
	if got["method"] != http.MethodPost {
		t.Errorf("logged method = %v, want POST", got["method"])
	}
	if got["path"] != "/auth/login" {
		t.Errorf("logged path = %v, want /auth/login", got["path"])
	}
}

// --- Correlation (Decision 7: single correlation point) ----------------

// TestCorrelation_NoProvider_RequestIDOnly proves the no-provider contract:
// the request-id surface keeps working byte-identically (preserve or
// generate 32-hex) while the span-derived headers (X-Trace-Id, Traceparent)
// stay absent — the honest "no tracing" state (Decision 12).
func TestCorrelation_NoProvider_RequestIDOnly(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	wrapped := Correlation("test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inside the wrapped handler the span context is invalid (no
		// provider): no trace id on the context, no span headers.
		if got := core.TraceIDFromContext(r.Context()); got != "" {
			t.Errorf("context trace_id = %q, want empty without a provider", got)
		}
	}))
	wrapped.ServeHTTP(w, r)

	got := w.Header().Get(core.HeaderRequestID)
	if got == "" {
		t.Fatal("response X-Request-Id is empty; want a generated id")
	}
	if len(got) != requestIDBytes*2 {
		t.Errorf("generated request id len = %d, want %d", len(got), requestIDBytes*2)
	}
	if r.Header.Get(core.HeaderRequestID) != got {
		t.Errorf("request header id = %q, want it to match response %q", r.Header.Get(core.HeaderRequestID), got)
	}
	if got := w.Header().Get(core.HeaderTraceID); got != "" {
		t.Errorf("X-Trace-Id = %q, want absent without a provider", got)
	}
	if got := w.Header().Get(core.HeaderTraceparent); got != "" {
		t.Errorf("Traceparent = %q, want absent without a provider", got)
	}
}

func TestCorrelation_PreservesIncomingRequestID(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	const incoming = "client-supplied-correlation-id"
	r.Header.Set(core.HeaderRequestID, incoming)
	wrapped := Correlation("test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	wrapped.ServeHTTP(w, r)

	if got := w.Header().Get(core.HeaderRequestID); got != incoming {
		t.Errorf("response request id = %q, want preserved %q", got, incoming)
	}
}

// TestCorrelation_WithProvider_StampsSpanHeaders drives the middleware with
// a REAL provider (in-memory exporter) and asserts the whole correlation
// contract on one response: X-Trace-Id == the request span's trace id, a
// parseable Traceparent carrying the same trace id + the span id, and the
// context trace_id visible to inner handlers. This is the regression
// boundary for "the wrapper sets Traceparent explicitly from sc" — otelhttp
// v0.68.0 does not inject response headers (verified upstream).
func TestCorrelation_WithProvider_StampsSpanHeaders(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(), tracing.WithExporter(exp))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
	// Reset the global provider so other tests in this package keep the
	// no-op default (tracing.Init does not restore it on shutdown).
	t.Cleanup(func() { otel.SetTracerProvider(trace.NewNoopTracerProvider()) })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	var ctxTraceID string
	var ctxSpanID string
	wrapped := Correlation("test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxTraceID = core.TraceIDFromContext(r.Context())
		ctxSpanID = trace.SpanFromContext(r.Context()).SpanContext().SpanID().String()
	}))
	wrapped.ServeHTTP(w, r)

	tid := w.Header().Get(core.HeaderTraceID)
	if tid == "" {
		t.Fatal("X-Trace-Id is empty; want the span trace id")
	}
	if len(tid) != 32 {
		t.Errorf("X-Trace-Id = %q, want 32-hex trace id", tid)
	}
	if ctxTraceID != tid {
		t.Errorf("context trace_id = %q, want X-Trace-Id %q (single source)", ctxTraceID, tid)
	}

	tp := w.Header().Get(core.HeaderTraceparent)
	if tp == "" {
		t.Fatal("Traceparent is empty; want the wrapper to set it from the span")
	}
	parts := strings.Split(tp, "-")
	if len(parts) != 4 || parts[0] != "00" {
		t.Fatalf("Traceparent %q not a 4-segment v00 header", tp)
	}
	if parts[1] != tid {
		t.Errorf("Traceparent trace id = %q, want %q", parts[1], tid)
	}
	if parts[2] == "" || parts[2] != ctxSpanID {
		t.Errorf("Traceparent span id = %q, want the live span %q", parts[2], ctxSpanID)
	}

	// The span really ran and exported.
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	if got := len(exp.GetSpans()); got == 0 {
		t.Fatal("expected at least one exported span from the Correlation-wrapped request")
	}
}

// TestCorrelation_WithProvider_HonorsIncomingTraceparent proves the span
// (and thus X-Trace-Id/Traceparent) preserves an incoming traceparent's
// trace id — the propagation contract the legacy middleware used to own.
func TestCorrelation_WithProvider_HonorsIncomingTraceparent(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(), tracing.WithExporter(exp))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
	t.Cleanup(func() { otel.SetTracerProvider(trace.NewNoopTracerProvider()) })

	const inTrace = "0af7651916cd43dd8448eb211c80319c"
	const inSpan = "b7ad6b7169203331"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(core.HeaderTraceparent, "00-"+inTrace+"-"+inSpan+"-01")
	wrapped := Correlation("test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	wrapped.ServeHTTP(w, r)

	if got := w.Header().Get(core.HeaderTraceID); got != inTrace {
		t.Errorf("X-Trace-Id = %q, want preserved trace %q", got, inTrace)
	}
}

// --- WithSubject round-trip ---------------------------------------------

func TestWithSubject_RoundTrip(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := SubjectFromContext(r); got != "" {
		t.Errorf("subject before WithSubject = %q, want empty", got)
	}
	r = r.WithContext(WithSubject(r.Context(), "subject-42"))
	if got := SubjectFromContext(r); got != "subject-42" {
		t.Errorf("subject after WithSubject = %q, want subject-42", got)
	}
}

// --- TrustedProxies: malformed XFF hops ---------------------------------

func TestTrustedProxies_UnparseableHop_ReturnsLeftNeighbor(t *testing.T) {
	t.Parallel()

	// XFF = "1.2.3.4, garbage, 10.0.0.1". Walking right-to-left:
	//   10.0.0.1 (trusted, peeled)
	//   "garbage" (unparseable) → stop; the entry to its left (1.2.3.4) is
	//   taken as the client boundary.
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 0)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4, garbage, 10.0.0.1")
	r.RemoteAddr = "10.0.0.1:443"
	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "1.2.3.4" {
		t.Errorf("unparseable hop: got %q, want 1.2.3.4 (left neighbor)", cap.got)
	}
}

func TestTrustedProxies_LeadingUnparseableHop_ReturnsRaw(t *testing.T) {
	t.Parallel()

	// XFF = "garbage, 10.0.0.1". Walking right-to-left:
	//   10.0.0.1 (trusted, peeled)
	//   "garbage" at i==0 (unparseable, no left neighbor) → return the raw
	//   token itself as the best-effort client value.
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 0)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "garbage, 10.0.0.1")
	r.RemoteAddr = "10.0.0.1:443"
	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "garbage" {
		t.Errorf("leading unparseable hop: got %q, want raw \"garbage\"", cap.got)
	}
}

func TestTrustedProxies_BudgetExhaustedAtLeftmost_ReturnsRaw(t *testing.T) {
	t.Parallel()

	// Single trusted hop, hops budget = 1, and that hop sits at i==0.
	// XFF = "10.0.0.5". Walking right-to-left:
	//   10.0.0.5 (trusted, hops 1→0, continue) — loop ends.
	// The whole list was trusted, so the leftmost entry (itself) is returned.
	//
	// To exercise the budget-exhausted-at-i==0 branch (line 108), use a list
	// where the budget runs out exactly on the leftmost trusted hop.
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 1)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Two trusted hops, budget 1: peel the rightmost, then budget==0 on the
	// leftmost trusted hop at i==0 → return that raw entry.
	r.Header.Set("X-Forwarded-For", "10.0.0.5, 10.0.0.6")
	r.RemoteAddr = "10.0.0.6:443"
	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "10.0.0.5" {
		t.Errorf("budget exhausted at leftmost: got %q, want 10.0.0.5", cap.got)
	}
}

// --- BaseURL XFF first-hop honoring -------------------------------------

func TestBaseURL_Nil(t *testing.T) {
	t.Parallel()

	if got := BaseURL(nil); got != "" {
		t.Errorf("BaseURL(nil) = %q, want empty", got)
	}
}

func TestBaseURL_XFFFirstHopOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		host    string
		tls     bool
		headers map[string]string
		want    string
	}{
		{
			name: "default http from host",
			host: "sso.internal:8080",
			want: "http://sso.internal:8080",
		},
		{
			name: "https from TLS when no XFP",
			host: "sso.example.com",
			tls:  true,
			want: "https://sso.example.com",
		},
		{
			name:    "x-forwarded-proto first hop of comma list",
			host:    "sso.example.com",
			headers: map[string]string{"X-Forwarded-Proto": "https, http"},
			want:    "https://sso.example.com",
		},
		{
			name:    "x-forwarded-host first hop of comma list",
			host:    "internal-host",
			headers: map[string]string{"X-Forwarded-Host": "public.example.com, internal-host"},
			want:    "http://public.example.com",
		},
		{
			name: "both forwarded headers, first hops, whitespace trimmed",
			host: "internal-host:9000",
			headers: map[string]string{
				"X-Forwarded-Proto": " https , http",
				"X-Forwarded-Host":  " edge.example.com , internal-host",
			},
			want: "https://edge.example.com",
		},
		{
			name:    "x-forwarded-proto overrides TLS scheme",
			host:    "sso.example.com",
			tls:     true,
			headers: map[string]string{"X-Forwarded-Proto": "http"},
			want:    "http://sso.example.com",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/whatever", nil)
			r.Host = tc.host
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := BaseURL(r); got != tc.want {
				t.Errorf("BaseURL() = %q, want %q", got, tc.want)
			}
		})
	}
}
