package tracing

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TracerName is the OTel instrumentation-library name every StartSpan call
// registers under. A single shared name keeps span provenance grep-able in
// a trace backend without every background package (audit, caep, cluster,
// migrate, ...) inventing its own otel.Tracer(...) call — Init already owns
// registering the global TracerProvider; StartSpan is the matching seam for
// acquiring spans off it, so callers never import go.opentelemetry.io/otel
// directly just to get a Tracer.
const TracerName = "github.com/yangwb1123/snaplink"

// StartSpan starts a span named name, parented to whatever span (if any)
// ctx already carries — exactly like otel.Tracer(...).Start, just without
// every caller repeating the Tracer(TracerName) lookup. Async/background
// callers that legitimately have no live parent by the time they run (see
// DetachedContext and ParentFromIDs) correctly get a fresh root span; that
// is the expected shape for a queue drained well after its triggering
// request returned, not an error condition.
//
// Callers MUST `defer span.End()`.
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return otel.Tracer(TracerName).Start(ctx, name, opts...)
}

// ParentSpanID returns the parent span ID of the LIVE span in ctx, or ""
// when ctx carries no valid span or the span is a trace root (no parent).
// audit.EventFromRequest uses it to stamp the REAL parent (Decision 8 of
// docs/design/middleware-observability-unified.md) instead of the legacy
// X-Parent-Span-Id header reconstruction — the span tree is the only
// source of truth. Requires a recording SDK span (the otelhttp request
// span); a non-recording / noop span has no parent information to expose.
func ParentSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}
	if ro, ok := span.(sdktrace.ReadOnlySpan); ok {
		if p := ro.Parent(); p.IsValid() {
			return p.SpanID().String()
		}
	}
	return ""
}

// DetachedContext returns a context carrying ONLY ctx's span context (no
// deadline, no cancellation, no other values) — the shape a goroutine
// dispatched off the request path needs: the triggering request's ctx is
// often cancelled or gone by the time the goroutine actually runs (see
// caep.Transmitter.deliver, audit.AsyncSink.deliver), so the goroutine
// deliberately does NOT inherit it, but the span link must still survive
// so the async work attributes back to the originating trace in a backend
// like Tempo/Jaeger instead of showing up as an orphan root.
//
// When ctx carries no valid span, the returned context is a plain
// context.Background() and the next StartSpan call roots a new trace —
// correct for a fully detached caller (e.g. a scheduler tick with no
// request in flight at all).
func DetachedContext(ctx context.Context) context.Context {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return context.Background()
	}
	return trace.ContextWithSpanContext(context.Background(), sc)
}

// ParentFromIDs attaches (traceIDHex, spanIDHex) to ctx as a REMOTE parent
// span context, for callers that only have W3C hex trace/span ids on hand
// rather than a live context to detach from — e.g. audit's AsyncSink, whose
// Record intentionally does NOT forward the request ctx into the worker (a
// cancelled request ctx must never abort delivery) but DOES stamp the ids
// onto the durable Event before dropping it (audit.Event.TraceID/SpanID;
// same 32/16-char hex wire shape as OTel's own TraceID/SpanID, so no
// translation beyond parsing is needed).
//
// ctx is returned unmodified when either id fails to parse (malformed or
// absent, e.g. a pre-tracing Event or an event recorded with no live
// request span) — the next StartSpan on the result then correctly roots a
// new trace rather than mis-parenting to a garbage span context.
func ParentFromIDs(ctx context.Context, traceIDHex, spanIDHex string) context.Context {
	tid, err := trace.TraceIDFromHex(traceIDHex)
	if err != nil {
		return ctx
	}
	sid, err := trace.SpanIDFromHex(spanIDHex)
	if err != nil {
		return ctx
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	return trace.ContextWithRemoteSpanContext(ctx, sc)
}

// SetError records err on span and flips its status to Error — the one
// call every async-path span in this codebase makes on failure, so each
// package doesn't repeat the RecordError + SetStatus pair (and doesn't
// need its own otel/codes import for it). No-op when err is nil, so call
// sites stay branch-free: `tracing.SetError(span, err)` right after the
// existing fail-handling code, unconditionally.
func SetError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}
