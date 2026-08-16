package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/platform/tracing"
	"github.com/yangwb1123/snaplink/shared/core"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestHandleHealth(t *testing.T) {
	t.Parallel()

	s := &Server{}
	s.issuer = "https://sso.example.com"
	r := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	ctx := core.NewContext(w, r)
	s.handleHealth(ctx)

	if w.Code != 200 {
		t.Errorf("handleHealth status = %d, want 200", w.Code)
	}
}

func TestHandleHealthWithIssuer(t *testing.T) {
	t.Parallel()

	s := &Server{}
	s.issuer = "https://sso.example.com"
	r := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	ctx := core.NewContext(w, r)
	s.handleHealth(ctx)

	if w.Code != 200 {
		t.Errorf("handleHealth status = %d, want 200", w.Code)
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer mytoken123")
	if got := bearerToken(r); got != "mytoken123" {
		t.Errorf("bearerToken() = %q, want mytoken123", got)
	}

	// No Authorization header
	r2 := httptest.NewRequest("GET", "/", nil)
	if got := bearerToken(r2); got != "" {
		t.Errorf("bearerToken() without header = %q, want empty", got)
	}
}

func TestErrorBody(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest("GET", "/", nil)
	ctx := core.NewContext(httptest.NewRecorder(), r)

	m := errorBody(ctx, "invalid_request")
	if m["error"] != "invalid_request" {
		t.Errorf("errorBody() = %v, want error=invalid_request", m)
	}
}

// TestErrorBody_NoTraceContext proves errorBody is an exact superset of
// the pre-trace-id behavior when the Tracing middleware never ran (no
// trace ID stashed on the request context): no trace_id key appears at
// all, rather than an empty-string one — callers that never had a trace
// ID keep byte-identical responses.
func TestErrorBody_NoTraceContext(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest("GET", "/", nil)
	ctx := core.NewContext(httptest.NewRecorder(), r)

	m := errorBody(ctx, "invalid_request")
	if _, present := m["trace_id"]; present {
		t.Errorf("errorBody() = %v, want no trace_id key when no trace context is present", m)
	}
}

// TestErrorBody_WithTraceContext proves errorBody surfaces the request's
// trace ID (as stashed by middleware.Correlation via core.WithTraceID) in the
// error envelope for client-side debugging correlation.
func TestErrorBody_WithTraceContext(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(core.WithTraceID(r.Context(), "trace-abc-123"))
	ctx := core.NewContext(httptest.NewRecorder(), r)

	m := errorBody(ctx, "invalid_request")
	if m["error"] != "invalid_request" {
		t.Errorf("errorBody() error = %q, want invalid_request", m["error"])
	}
	if m["trace_id"] != "trace-abc-123" {
		t.Errorf("errorBody() trace_id = %q, want trace-abc-123", m["trace_id"])
	}
}

// TestErrorBody_EndToEndViaCorrelationMiddleware drives a real handler
// through middleware.Correlation (Decision 7: the OTel span is the only
// propagation source) to prove the wiring holds end-to-end, not just when
// a test hand-crafts the context. Runs with a REAL provider (in-memory
// exporter) — the no-op provider yields invalid span contexts and thus an
// empty trace_id, which is the deliberate no-tracing contract, not the
// regression this test guards.
func TestErrorBody_EndToEndViaCorrelationMiddleware(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(), tracing.WithExporter(exp))
	if err != nil {
		t.Fatalf("tracing.Init: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
	t.Cleanup(func() { otel.SetTracerProvider(trace.NewNoopTracerProvider()) })

	s := &Server{}
	s.issuer = "https://sso.example.com"

	r := httptest.NewRequest("GET", "/authz-policy-bundle", nil)
	w := httptest.NewRecorder()
	wrapped := middleware.Correlation("test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleAuthzPolicyBundle(core.NewContext(w, r))
	}))
	wrapped.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (no permissions provider wired)", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// errorBody surfaces core.TraceIDFromContext — the Correlation middleware
	// stamps it from the live span, so it must equal the X-Trace-Id header.
	if body["trace_id"] == "" {
		t.Errorf("response body = %v, want non-empty trace_id after Correlation middleware ran", body)
	}
	if got := w.Header().Get(core.HeaderTraceID); body["trace_id"] != got {
		t.Errorf("error-body trace_id = %q, want X-Trace-Id header %q (single source)", body["trace_id"], got)
	}
}
