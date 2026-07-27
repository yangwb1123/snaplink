package memory_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/platform/cluster/memory"
	"github.com/yangwb1123/snaplink/platform/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// initSpanExporter wires an InMemoryExporter as the global TracerProvider
// for one test. Deliberately NOT t.Parallel(): every other test in this
// package runs in parallel and the OTel SDK's TracerProvider is
// process-global.
func initSpanExporter(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(), tracing.WithExporter(exp))
	if err != nil {
		t.Fatalf("tracing.Init: %v", err)
	}
	t.Cleanup(func() {
		if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
			_ = tp.ForceFlush(context.Background())
		}
		_ = shutdown(context.Background())
	})
	return exp
}

func flushAndSpans(t *testing.T, exp *tracetest.InMemoryExporter) tracetest.SpanStubs {
	t.Helper()
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	return exp.GetSpans()
}

func findBusSpan(spans tracetest.SpanStubs, name string) *tracetest.SpanStub {
	for i := range spans {
		if spans[i].Name == name {
			return &spans[i]
		}
	}
	return nil
}

func TestPublish_CreatesSpan_ChildOfCtx(t *testing.T) {
	exp := initSpanExporter(t)

	b := memory.New()
	defer func() { _ = b.Close() }()

	ctx, parent := otel.Tracer("test").Start(context.Background(), "request")
	if err := b.Publish(ctx, cluster.Event{Kind: cluster.KindClientChange, Key: "c-1"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	parent.End()

	spans := flushAndSpans(t, exp)
	span := findBusSpan(spans, "cluster.bus.publish")
	if span == nil {
		t.Fatalf("no cluster.bus.publish span; got %d spans", len(spans))
	}
	if span.SpanContext.TraceID() != parent.SpanContext().TraceID() {
		t.Errorf("trace id = %s, want parent's %s", span.SpanContext.TraceID(), parent.SpanContext().TraceID())
	}
	if span.Parent.SpanID() != parent.SpanContext().SpanID() {
		t.Errorf("parent span id = %s, want %s", span.Parent.SpanID(), parent.SpanContext().SpanID())
	}
	var sawBackend, sawKind bool
	for _, attr := range span.Attributes {
		switch string(attr.Key) {
		case "cluster.bus.backend":
			sawBackend = attr.Value.AsString() == "memory"
		case "cluster.bus.kind":
			sawKind = attr.Value.AsString() == string(cluster.KindClientChange)
		}
	}
	if !sawBackend {
		t.Error("missing/wrong cluster.bus.backend attribute")
	}
	if !sawKind {
		t.Error("missing/wrong cluster.bus.kind attribute")
	}
}

func TestPublish_AfterClose_SpanRecordsError(t *testing.T) {
	exp := initSpanExporter(t)

	b := memory.New()
	_ = b.Close()

	if err := b.Publish(context.Background(), cluster.Event{Kind: cluster.KindClientChange}); err == nil {
		t.Fatal("expected error publishing to a closed bus")
	}

	spans := flushAndSpans(t, exp)
	span := findBusSpan(spans, "cluster.bus.publish")
	if span == nil {
		t.Fatal("no cluster.bus.publish span")
	}
	if span.Status.Code != codes.Error {
		t.Errorf("status code = %v, want Error", span.Status.Code)
	}
}

func TestSubscribe_CreatesSpan_ChildOfCtx(t *testing.T) {
	exp := initSpanExporter(t)

	b := memory.New()
	defer func() { _ = b.Close() }()

	ctx, parent := otel.Tracer("test").Start(context.Background(), "boot")
	if _, err := b.Subscribe(ctx); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	parent.End()

	spans := flushAndSpans(t, exp)
	span := findBusSpan(spans, "cluster.bus.subscribe")
	if span == nil {
		t.Fatalf("no cluster.bus.subscribe span; got %d spans", len(spans))
	}
	if span.SpanContext.TraceID() != parent.SpanContext().TraceID() {
		t.Errorf("trace id = %s, want parent's %s", span.SpanContext.TraceID(), parent.SpanContext().TraceID())
	}
}

func TestSubscribe_AfterClose_SpanRecordsError(t *testing.T) {
	exp := initSpanExporter(t)

	b := memory.New()
	_ = b.Close()

	if _, err := b.Subscribe(context.Background()); err == nil {
		t.Fatal("expected error subscribing to a closed bus")
	}

	spans := flushAndSpans(t, exp)
	span := findBusSpan(spans, "cluster.bus.subscribe")
	if span == nil {
		t.Fatal("no cluster.bus.subscribe span")
	}
	if span.Status.Code != codes.Error {
		t.Errorf("status code = %v, want Error", span.Status.Code)
	}
}
