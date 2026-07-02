package auditsink

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit/auditspi"
	"github.com/snaplink/sso/platform/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// initSpanExporter wires an InMemoryExporter as the global provider for the
// duration of one test. Deliberately not t.Parallel(): the OTel SDK's
// TracerProvider is process-global, and this package's other tests run in
// parallel — keeping this one sequential avoids racing the registration.
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

func flush(t *testing.T) {
	t.Helper()
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
}

// TestWebhookSink_Record_CreatesChildSpan proves Record's span is parented
// on the caller's live span (the shape AsyncSink.deliver hands it, and the
// shape a synchronous Recorder call hands it directly).
func TestWebhookSink_Record_CreatesChildSpan(t *testing.T) {
	exp := initSpanExporter(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ctx, parent := otel.Tracer("test").Start(context.Background(), "parent")
	s := NewWebhookSink(srv.URL)
	if err := s.Record(ctx, &auditspi.Event{Type: "test_event"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	parent.End()
	flush(t)

	spans := exp.GetSpans()
	child := findSpan(spans, "audit.webhook.deliver")
	if child == nil {
		t.Fatalf("no audit.webhook.deliver span; got %d spans", len(spans))
	}
	if child.SpanContext.TraceID() != parent.SpanContext().TraceID() {
		t.Errorf("child trace id = %s, want parent's %s", child.SpanContext.TraceID(), parent.SpanContext().TraceID())
	}
	if child.Parent.SpanID() != parent.SpanContext().SpanID() {
		t.Errorf("child parent span id = %s, want %s", child.Parent.SpanID(), parent.SpanContext().SpanID())
	}
	var sawStatus bool
	for _, attr := range child.Attributes {
		if string(attr.Key) == "http.response.status_code" && attr.Value.AsInt64() == http.StatusNoContent {
			sawStatus = true
		}
	}
	if !sawStatus {
		t.Error("missing http.response.status_code attribute")
	}
}

// TestWebhookSink_Record_ErrorSetsSpanStatus proves a non-2xx response
// flips the span to Error, matching the returned error.
func TestWebhookSink_Record_ErrorSetsSpanStatus(t *testing.T) {
	exp := initSpanExporter(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	s := NewWebhookSink(srv.URL)
	err := s.Record(context.Background(), &auditspi.Event{Type: "test_event"})
	if err == nil {
		t.Fatal("expected error on 4xx response")
	}
	flush(t)

	span := findSpan(exp.GetSpans(), "audit.webhook.deliver")
	if span == nil {
		t.Fatal("no audit.webhook.deliver span")
	}
	if span.Status.Code != codes.Error {
		t.Errorf("status code = %v, want Error", span.Status.Code)
	}
	if span.Status.Description != err.Error() {
		t.Errorf("status description = %q, want %q", span.Status.Description, err.Error())
	}
}

// flakyThenOKSink fails failN times then succeeds, for exercising the
// retry loop's span attempt-count attribute.
type flakyThenOKSink struct {
	failN int
	calls int
}

func (f *flakyThenOKSink) Record(context.Context, *auditspi.Event) error {
	f.calls++
	if f.calls <= f.failN {
		return errors.New("transient failure")
	}
	return nil
}
func (f *flakyThenOKSink) Get(context.Context, string) (*auditspi.Event, error) {
	return nil, ErrSinkWriteOnly
}
func (f *flakyThenOKSink) Query(context.Context, auditspi.Query) ([]*auditspi.Event, error) {
	return nil, ErrSinkWriteOnly
}

// TestRetryingSink_Record_SpanCarriesAttemptCount proves the whole retry
// chain is one span (not one per attempt) carrying the final attempt count,
// so a slow/flaky sink is visible as ONE audit.sink.retry span with nested
// per-attempt child spans from the inner sink, rather than an unbounded
// span fan-out.
func TestRetryingSink_Record_SpanCarriesAttemptCount(t *testing.T) {
	exp := initSpanExporter(t)

	inner := &flakyThenOKSink{failN: 2}
	r := NewRetryingSink(inner,
		WithRetryMaxAttempts(5),
		WithRetryInitialBackoff(time.Millisecond),
		WithRetryMaxBackoff(2*time.Millisecond),
	)
	if err := r.Record(context.Background(), &auditspi.Event{Type: "test_event"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	flush(t)

	spans := exp.GetSpans()
	var retrySpans int
	var attemptsSeen int64
	for _, s := range spans {
		if s.Name != "audit.sink.retry" {
			continue
		}
		retrySpans++
		for _, attr := range s.Attributes {
			if string(attr.Key) == "audit.retry.attempts" {
				attemptsSeen = attr.Value.AsInt64()
			}
		}
		if s.Status.Code == codes.Error {
			t.Errorf("eventual success must not leave the span in Error status: %+v", s.Status)
		}
	}
	if retrySpans != 1 {
		t.Fatalf("got %d audit.sink.retry spans, want exactly 1", retrySpans)
	}
	if attemptsSeen != 3 {
		t.Errorf("audit.retry.attempts = %d, want 3 (2 failures + 1 success)", attemptsSeen)
	}
}

// TestRetryingSink_Record_AllAttemptsFail_SpanError proves exhausting every
// retry surfaces as an Error-status span carrying the last error.
func TestRetryingSink_Record_AllAttemptsFail_SpanError(t *testing.T) {
	exp := initSpanExporter(t)

	inner := &flakyThenOKSink{failN: 99}
	r := NewRetryingSink(inner,
		WithRetryMaxAttempts(2),
		WithRetryInitialBackoff(time.Millisecond),
		WithRetryMaxBackoff(2*time.Millisecond),
	)
	err := r.Record(context.Background(), &auditspi.Event{Type: "test_event"})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	flush(t)

	span := findSpan(exp.GetSpans(), "audit.sink.retry")
	if span == nil {
		t.Fatal("no audit.sink.retry span")
	}
	if span.Status.Code != codes.Error {
		t.Errorf("status code = %v, want Error", span.Status.Code)
	}
	for _, attr := range span.Attributes {
		if string(attr.Key) == "audit.retry.attempts" && attr.Value.AsInt64() != 2 {
			t.Errorf("audit.retry.attempts = %d, want 2 (maxAttempts exhausted)", attr.Value.AsInt64())
		}
	}
}
