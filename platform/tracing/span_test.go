package tracing_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/platform/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// initExporter wires an InMemoryExporter as the global provider and
// returns it plus a flush func, mirroring the pattern in tracing_test.go.
func initExporter(t *testing.T) (*tracetest.InMemoryExporter, func()) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(), tracing.WithExporter(exp))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	flush := func() {
		if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
			_ = tp.ForceFlush(context.Background())
		}
		_ = shutdown(context.Background())
	}
	return exp, flush
}

func TestStartSpan_ChildOfLiveParent(t *testing.T) {
	exp, flush := initExporter(t)
	defer flush()

	ctx, parent := otel.Tracer("test").Start(context.Background(), "parent")
	_, child := tracing.StartSpan(ctx, "audit.sink.deliver")
	child.End()
	parent.End()

	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	spans := exp.GetSpans()
	var childSpan, parentSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "audit.sink.deliver" {
			childSpan = &spans[i]
		}
		if spans[i].Name == "parent" {
			parentSpan = &spans[i]
		}
	}
	if childSpan == nil || parentSpan == nil {
		t.Fatalf("missing spans; got %d", len(spans))
	}
	if childSpan.SpanContext.TraceID() != parentSpan.SpanContext.TraceID() {
		t.Errorf("child trace id = %s, want parent's %s", childSpan.SpanContext.TraceID(), parentSpan.SpanContext.TraceID())
	}
	if childSpan.Parent.SpanID() != parentSpan.SpanContext.SpanID() {
		t.Errorf("child parent span id = %s, want %s", childSpan.Parent.SpanID(), parentSpan.SpanContext.SpanID())
	}
}

func TestStartSpan_NoParent_RootsNewTrace(t *testing.T) {
	_, flush := initExporter(t)
	defer flush()

	_, span := tracing.StartSpan(context.Background(), "migrate.run")
	defer span.End()

	sc := oteltrace.SpanContextFromContext(context.Background())
	if sc.IsValid() {
		t.Fatal("test setup: background context should carry no span")
	}
	// A fresh trace id was minted (not the zero value).
	if !span.SpanContext().TraceID().IsValid() {
		t.Error("expected a freshly-minted, valid trace id for a rootless StartSpan")
	}
}

func TestDetachedContext_PreservesSpanLink(t *testing.T) {
	_, flush := initExporter(t)
	defer flush()

	ctx, parent := otel.Tracer("test").Start(context.Background(), "request")
	defer parent.End()

	// Simulate the "cancelled by the time the goroutine runs" scenario: a
	// child context that's already been cancelled.
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()

	detached := tracing.DetachedContext(cancelledCtx)
	if detached.Err() != nil {
		t.Errorf("DetachedContext must not inherit cancellation, got Err() = %v", detached.Err())
	}
	if _, ok := detached.Deadline(); ok {
		t.Error("DetachedContext must not inherit a deadline")
	}
	sc := oteltrace.SpanContextFromContext(detached)
	if !sc.IsValid() {
		t.Fatal("DetachedContext dropped a valid parent span context")
	}
	if sc.TraceID() != parent.SpanContext().TraceID() {
		t.Errorf("detached trace id = %s, want %s", sc.TraceID(), parent.SpanContext().TraceID())
	}
}

func TestDetachedContext_NoSpan_ReturnsPlainBackground(t *testing.T) {
	detached := tracing.DetachedContext(context.Background())
	sc := oteltrace.SpanContextFromContext(detached)
	if sc.IsValid() {
		t.Error("expected no span context when input carried none")
	}
}

func TestParentFromIDs_ValidIDs_BecomesParent(t *testing.T) {
	_, flush := initExporter(t)
	defer flush()

	const traceID = "0af7651916cd43dd8448eb211c80319c" // 32 hex chars
	const spanID = "b7ad6b7169203331"                  // 16 hex chars

	ctx := tracing.ParentFromIDs(context.Background(), traceID, spanID)
	_, span := tracing.StartSpan(ctx, "audit.sink.deliver")
	defer span.End()

	if span.SpanContext().TraceID().String() != traceID {
		t.Errorf("trace id = %s, want %s", span.SpanContext().TraceID(), traceID)
	}
}

func TestParentFromIDs_InvalidIDs_LeavesContextUnchanged(t *testing.T) {
	base := context.WithValue(context.Background(), ctxKey{}, "marker")
	out := tracing.ParentFromIDs(base, "not-hex", "also-not-hex")
	if out.Value(ctxKey{}) != "marker" {
		t.Error("ParentFromIDs must return ctx unchanged on malformed ids")
	}
	sc := oteltrace.SpanContextFromContext(out)
	if sc.IsValid() {
		t.Error("malformed ids must not produce a valid span context")
	}
}

type ctxKey struct{}

func TestSetError_Nil_NoOp(t *testing.T) {
	exp, flush := initExporter(t)
	defer flush()

	_, span := tracing.StartSpan(context.Background(), "noop")
	tracing.SetError(span, nil) // must not panic, must not touch status
	span.End()

	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Status.Code == codes.Error {
		t.Error("SetError(span, nil) must not set an Error status")
	}
	if len(spans[0].Events) != 0 {
		t.Errorf("SetError(span, nil) must not record an event, got %+v", spans[0].Events)
	}
}

func TestSetError_RecordsAndSetsStatus(t *testing.T) {
	exp, flush := initExporter(t)
	defer flush()

	_, span := tracing.StartSpan(context.Background(), "audit.sink.deliver")
	tracing.SetError(span, errors.New("boom"))
	span.End()

	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Status.Code != codes.Error {
		t.Errorf("status code = %v, want Error", s.Status.Code)
	}
	if s.Status.Description != "boom" {
		t.Errorf("status description = %q, want boom", s.Status.Description)
	}
	if len(s.Events) != 1 || s.Events[0].Name != "exception" {
		t.Errorf("expected one recorded exception event, got %+v", s.Events)
	}
}
