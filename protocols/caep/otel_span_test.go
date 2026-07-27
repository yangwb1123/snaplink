package caep_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/tracing"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/shared/core"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// initSpanExporter wires an InMemoryExporter as the global TracerProvider
// for one test. Deliberately NOT t.Parallel(): every other test in this
// package runs in parallel, and the OTel SDK's TracerProvider is
// process-global — running unparallelized keeps this registration from
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

func findCAEPSpan(spans tracetest.SpanStubs, name string) *tracetest.SpanStub {
	for i := range spans {
		if spans[i].Name == name {
			return &spans[i]
		}
	}
	return nil
}

func flushSpans(t *testing.T) {
	t.Helper()
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
}

// TestTransmitter_Deliver_CreatesSpan_ChildOfRecordCtx proves the async
// delivery goroutine's span is parented on Record's caller's live span,
// even though the goroutine itself never inherits Record's ctx (see
// tracing.DetachedContext).
func TestTransmitter_Deliver_CreatesSpan_ChildOfRecordCtx(t *testing.T) {
	exp := initSpanExporter(t)

	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv)))

	parentCtx, parent := otel.Tracer("test").Start(context.Background(), "request")
	_ = tx.Record(parentCtx, &audit.Event{
		Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u",
	})
	waitFor(t, func() bool { return recv.count() == 1 }, "SET received")
	if err := tx.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	parent.End()
	flushSpans(t)

	spans := exp.GetSpans()
	span := findCAEPSpan(spans, "caep.transmitter.deliver")
	if span == nil {
		t.Fatalf("no caep.transmitter.deliver span; got %d spans", len(spans))
	}
	if span.SpanContext.TraceID() != parent.SpanContext().TraceID() {
		t.Errorf("trace id = %s, want parent's %s", span.SpanContext.TraceID(), parent.SpanContext().TraceID())
	}
	if span.Parent.SpanID() != parent.SpanContext().SpanID() {
		t.Errorf("parent span id = %s, want %s", span.Parent.SpanID(), parent.SpanContext().SpanID())
	}
	var sawClientID, sawOutcome bool
	for _, attr := range span.Attributes {
		switch string(attr.Key) {
		case "caep.client_id":
			sawClientID = attr.Value.AsString() == "owner"
		case "outcome":
			sawOutcome = attr.Value.AsString() == caep.OutcomeSuccess
		}
	}
	if !sawClientID {
		t.Error("missing/wrong caep.client_id attribute")
	}
	if !sawOutcome {
		t.Error("missing/wrong outcome attribute")
	}
}

// TestTransmitter_Deliver_NoParent_RootsSpan proves a Record call with no
// live span (the common case: audit recording usually happens off a
// background goroutine already, e.g. an admin action processed async)
// still produces a usable span — a fresh root, not a crash.
func TestTransmitter_Deliver_NoParent_RootsSpan(t *testing.T) {
	exp := initSpanExporter(t)

	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv)))

	_ = tx.Record(context.Background(), &audit.Event{
		Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u",
	})
	waitFor(t, func() bool { return recv.count() == 1 }, "SET received")
	if err := tx.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	flushSpans(t)

	span := findCAEPSpan(exp.GetSpans(), "caep.transmitter.deliver")
	if span == nil {
		t.Fatal("no caep.transmitter.deliver span")
	}
	if !span.SpanContext.TraceID().IsValid() {
		t.Error("expected a freshly-minted valid trace id")
	}
	if span.Parent.IsValid() {
		t.Error("expected no parent when Record's ctx carried no live span")
	}
}

// TestTransmitter_Deliver_ErrorSetsSpanStatus proves a non-retryable
// receiver failure flips the span to Error status and records the outcome.
func TestTransmitter_Deliver_ErrorSetsSpanStatus(t *testing.T) {
	exp := initSpanExporter(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // non-retryable per retryableDeliveryError
	}))
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	tx := caep.NewTransmitter(iss, store,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithMetric(metric.record),
	)

	_ = tx.Record(context.Background(), &audit.Event{
		Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u",
	})
	waitFor(t, func() bool { return metric.has(caep.OutcomeFailed) }, "failed outcome recorded")
	if err := tx.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	flushSpans(t)

	span := findCAEPSpan(exp.GetSpans(), "caep.transmitter.deliver")
	if span == nil {
		t.Fatal("no caep.transmitter.deliver span")
	}
	if span.Status.Code != codes.Error {
		t.Errorf("status code = %v, want Error", span.Status.Code)
	}
	var sawOutcome bool
	for _, attr := range span.Attributes {
		if string(attr.Key) == "outcome" {
			sawOutcome = attr.Value.AsString() == caep.OutcomeFailed
		}
	}
	if !sawOutcome {
		t.Error("missing/wrong outcome=failed attribute")
	}
}

// TestTransmitter_Deliver_RetrySpan_IsSingleSpanWithEvents proves the retry
// chain stays ONE span (not one per attempt): re-attempts land as span
// events, so a flaky receiver never fans a SET delivery out into an
// unbounded number of spans.
func TestTransmitter_Deliver_RetrySpan_IsSingleSpanWithEvents(t *testing.T) {
	exp := initSpanExporter(t)

	recv := &flakyReceiver{failures: 2}
	srv := httptest.NewTLSServer(recv.handler())
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithDeliveryRetry(5),
		caep.WithDeliveryRetryBackoff(time.Millisecond, 5*time.Millisecond),
	)

	_ = tx.Record(context.Background(), &audit.Event{
		Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u",
	})
	waitFor(t, func() bool { return recv.acceptedCount() == 1 }, "SET accepted after retries")
	if err := tx.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	flushSpans(t)

	spans := exp.GetSpans()
	var deliverSpans int
	var span *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "caep.transmitter.deliver" {
			deliverSpans++
			span = &spans[i]
		}
	}
	if deliverSpans != 1 {
		t.Fatalf("got %d caep.transmitter.deliver spans, want exactly 1", deliverSpans)
	}
	if len(span.Events) != 2 {
		t.Errorf("got %d retry span events, want 2 (matching the 2 induced failures)", len(span.Events))
	}
	for _, ev := range span.Events {
		if ev.Name != "retry" {
			t.Errorf("event name = %q, want retry", ev.Name)
		}
	}
}
