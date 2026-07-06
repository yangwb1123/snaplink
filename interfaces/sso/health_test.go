package sso

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/shared/core"
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
// trace ID (as stashed by middleware.Tracing via core.WithTraceID) in the
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

// TestErrorBody_EndToEndViaTracingMiddleware drives a real handler through
// middleware.Tracing() (the middleware that populates the trace ID on the
// request context in production) to prove the wiring holds end-to-end, not
// just when a test hand-crafts the context.
func TestErrorBody_EndToEndViaTracingMiddleware(t *testing.T) {
	t.Parallel()

	s := &Server{}
	s.issuer = "https://sso.example.com"

	r := httptest.NewRequest("GET", "/authz-policy-bundle", nil)
	w := httptest.NewRecorder()
	ctx := core.NewContext(w, r)

	middleware.Tracing()(ctx) // populates core.WithTraceID on the request context
	s.handleAuthzPolicyBundle(ctx)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (no permissions provider wired)", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["trace_id"] == "" {
		t.Errorf("response body = %v, want non-empty trace_id after Tracing middleware ran", body)
	}
}
