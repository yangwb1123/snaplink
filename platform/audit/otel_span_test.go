package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/platform/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

var errAsyncTestFailure = errors.New("audit: test-injected delivery failure")

// initSpanExporter wires an InMemoryExporter as the global provider for the
// duration of one test. Deliberately NOT t.Parallel() — this package has
// many parallel-marked sibling tests, and the OTel SDK's TracerProvider is
// process-global; running unparallelized keeps this registration from
// racing another test's.
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

func findSpan(spans tracetest.SpanStubs, name string) *tracetest.SpanStub {
	for i := range spans {
		if spans[i].Name == name {
			return &spans[i]
		}
	}
	return nil
}

// TestAsyncSink_Deliver_CreatesSpan proves the async worker wraps every
// per-event delivery in an audit.sink.deliver span, tagged with the inner
// sink's type — Close drains the queue synchronously, so by the time it
// returns the span has already been ended.
func TestAsyncSink_Deliver_CreatesSpan(t *testing.T) {
	exp := initSpanExporter(t)

	inner := NewMemorySink(0)
	a := NewAsyncSink(inner)
	a.Start()
	if err := a.Record(context.Background(), &Event{Type: "test_event"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	spans := exp.GetSpans()
	span := findSpan(spans, "audit.sink.deliver")
	if span == nil {
		t.Fatalf("no audit.sink.deliver span; got %d spans", len(spans))
	}
	var sawSinkType, sawEventType bool
	for _, attr := range span.Attributes {
		switch string(attr.Key) {
		case "audit.sink.type":
			sawSinkType = attr.Value.AsString() != ""
		case "audit.event_type":
			sawEventType = attr.Value.AsString() == "test_event"
		}
	}
	if !sawSinkType {
		t.Error("missing/empty audit.sink.type attribute")
	}
	if !sawEventType {
		t.Error("missing/wrong audit.event_type attribute")
	}
}

// TestAsyncSink_Deliver_ParentsOnEventTraceID proves the async span links
// back to the ORIGINATING request's trace via the Event's stamped
// TraceID/SpanID — the only surviving handle once Record deliberately
// drops the request ctx (see the comment on AsyncSink.Record).
func TestAsyncSink_Deliver_ParentsOnEventTraceID(t *testing.T) {
	exp := initSpanExporter(t)

	const traceID = "0af7651916cd43dd8448eb211c80319c"
	const spanID = "b7ad6b7169203331"

	inner := NewMemorySink(0)
	a := NewAsyncSink(inner)
	a.Start()
	e := &Event{Type: "test_event", TraceID: traceID, SpanID: spanID}
	if err := a.Record(context.Background(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	span := findSpan(exp.GetSpans(), "audit.sink.deliver")
	if span == nil {
		t.Fatal("no audit.sink.deliver span")
	}
	if got := span.SpanContext.TraceID().String(); got != traceID {
		t.Errorf("trace id = %s, want %s (Event trace id not honored as parent)", got, traceID)
	}
	if got := span.Parent.SpanID().String(); got != spanID {
		t.Errorf("parent span id = %s, want %s", got, spanID)
	}
}

// TestAsyncSink_Deliver_NoEventTraceID_RootsSpan proves an Event recorded
// without trace ids (e.g. pre-tracing-middleware) still gets a usable span
// — a fresh root, not a crash or a garbage parent.
func TestAsyncSink_Deliver_NoEventTraceID_RootsSpan(t *testing.T) {
	exp := initSpanExporter(t)

	inner := NewMemorySink(0)
	a := NewAsyncSink(inner)
	a.Start()
	if err := a.Record(context.Background(), &Event{Type: "test_event"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	span := findSpan(exp.GetSpans(), "audit.sink.deliver")
	if span == nil {
		t.Fatal("no audit.sink.deliver span")
	}
	if !span.SpanContext.TraceID().IsValid() {
		t.Error("expected a freshly-minted valid trace id when the Event carries none")
	}
	if span.Parent.IsValid() {
		t.Error("expected no parent when the Event carries no trace ids")
	}
}

// TestAsyncSink_DeliverBatch_CreatesSpan proves the batch worker path wraps
// each RecordBatch call in an audit.sink.deliver_batch span carrying the
// batch size.
func TestAsyncSink_DeliverBatch_CreatesSpan(t *testing.T) {
	exp := initSpanExporter(t)

	inner := NewMemorySink(0)
	a := NewBatchAsyncSink(inner, 4, 64)
	a.Start()
	for i := 0; i < 5; i++ {
		if err := a.Record(context.Background(), &Event{Type: "test_event"}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	spans := exp.GetSpans()
	found := false
	for _, s := range spans {
		if s.Name != "audit.sink.deliver_batch" {
			continue
		}
		found = true
		for _, attr := range s.Attributes {
			if string(attr.Key) == "audit.batch_size" && attr.Value.AsInt64() <= 0 {
				t.Errorf("audit.batch_size = %d, want > 0", attr.Value.AsInt64())
			}
		}
	}
	if !found {
		t.Fatalf("no audit.sink.deliver_batch span; got %d spans", len(spans))
	}
}

// TestAsyncSink_Deliver_ErrorSetsSpanStatus proves an inner-sink failure is
// recorded on the span (RecordError + Error status), not just swallowed
// into the drop counters.
func TestAsyncSink_Deliver_ErrorSetsSpanStatus(t *testing.T) {
	exp := initSpanExporter(t)

	inner := sinkFunc(func(context.Context, *Event) error { return errAsyncTestFailure })
	a := NewAsyncSink(inner)
	a.Start()
	if err := a.Record(context.Background(), &Event{Type: "test_event"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	span := findSpan(exp.GetSpans(), "audit.sink.deliver")
	if span == nil {
		t.Fatal("no audit.sink.deliver span")
	}
	if span.Status.Code != codes.Error {
		t.Errorf("status code = %v, want Error", span.Status.Code)
	}
	if span.Status.Description != errAsyncTestFailure.Error() {
		t.Errorf("status description = %q, want %q", span.Status.Description, errAsyncTestFailure.Error())
	}
}
