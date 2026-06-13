package tracing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/tracing"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestInit_NoEndpoint_NoOp(t *testing.T) {
	// With no endpoint configured and no env var set, Init is a no-op
	// and returns a no-op shutdown the caller can defer safely.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := tracing.Init(context.Background())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown must be non-nil even in no-op mode")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("no-op shutdown returned error: %v", err)
	}
}

func TestInit_WithExporter_RegistersProvider(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(),
		tracing.WithServiceName("test-svc"),
		tracing.WithExporter(exp),
	)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	// Emit a span via the now-global tracer.
	tracer := otel.Tracer("test")
	_, span := tracer.Start(context.Background(), "manual-span")
	span.End()

	// Force flush so the in-memory exporter sees it.
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Name != "manual-span" {
		t.Errorf("span name = %q, want manual-span", spans[0].Name)
	}
}

func TestMiddleware_GeneratesSpanPerRequest(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(),
		tracing.WithExporter(exp),
	)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	mw := tracing.Middleware("test-op")
	called := false
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if !called {
		t.Error("inner handler not invoked")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	// Flush + assert.
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span from the middleware-wrapped request")
	}
	// otelhttp may emit nested spans (e.g. read/write); the outermost
	// should carry the operation name we supplied.
	found := false
	for _, s := range spans {
		if s.Name == "test-op" {
			found = true
			break
		}
	}
	if !found {
		var names []string
		for _, s := range spans {
			names = append(names, s.Name)
		}
		t.Errorf("no span named %q; got %v", "test-op", names)
	}
}

func TestMiddleware_HonorsIncomingTraceparent(t *testing.T) {
	// Incoming W3C traceparent should become the parent of the
	// middleware-created span — proves the propagator is wired.
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(), tracing.WithExporter(exp))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	mw := tracing.Middleware("test-op")
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 00-{32-char trace-id}-{16-char span-id}-{flags}
	const traceID = "0af7651916cd43dd8448eb211c80319c"
	const spanID = "b7ad6b7169203331"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("traceparent", "00-"+traceID+"-"+spanID+"-01")

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("no spans")
	}
	// Find the span carrying our operation name; its TraceID should
	// match the incoming traceparent.
	for _, s := range spans {
		if s.Name != "test-op" {
			continue
		}
		if s.SpanContext.TraceID().String() != traceID {
			t.Errorf("trace id = %s, want %s (traceparent not honored)", s.SpanContext.TraceID(), traceID)
		}
		return
	}
	t.Errorf("operation span not found in %d spans", len(spans))
}
