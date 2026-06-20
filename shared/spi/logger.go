package spi

import "context"

// Logger is the interface for SDK logging.
type Logger interface {
	Info(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
	Debug(msg string, keysAndValues ...any)
}

// ContextLogger is an OPTIONAL extension of [Logger]. A logger that
// implements it additionally accepts a context.Context, letting the SDK
// thread correlation data (a W3C trace id) onto each log line so ops logs
// can be joined to traces + audit events. The base [Logger] signature has
// no context, so it structurally cannot carry the trace id — this is the
// back-compat seam that adds one without breaking that contract.
//
// The SDK type-asserts a wired [Logger] to ContextLogger and, when
// present, routes the highest-value auth log sites through the *Ctx
// variants; otherwise it falls back to the plain [Logger] methods. A
// logger that does NOT implement ContextLogger keeps working byte-for-byte
// (no trace id, no panic).
type ContextLogger interface {
	Logger
	InfoCtx(ctx context.Context, msg string, keysAndValues ...any)
	ErrorCtx(ctx context.Context, msg string, keysAndValues ...any)
	DebugCtx(ctx context.Context, msg string, keysAndValues ...any)
}

// traceIDContextKey is the unexported type for the trace-id context value.
// A distinct type (not a bare string) prevents collisions with any other
// package stashing a value on the same context.
type traceIDContextKey struct{}

// ContextWithTraceID returns a copy of ctx carrying the W3C trace id. The
// SDK stamps it from the request's traceparent before calling a
// [ContextLogger]'s *Ctx method; the logger reads it back with
// [TraceIDFromContext]. Empty tid returns ctx unchanged so a request
// without a trace adds no value and the logger omits the field.
func ContextWithTraceID(ctx context.Context, tid string) context.Context {
	if tid == "" {
		return ctx
	}
	return context.WithValue(ctx, traceIDContextKey{}, tid)
}

// TraceIDFromContext returns the W3C trace id stamped by
// [ContextWithTraceID], or "" when absent. A ContextLogger implementation
// uses it to decide whether to append a trace_id field.
func TraceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	tid, _ := ctx.Value(traceIDContextKey{}).(string)
	return tid
}

// NopLogger discards all log output.
type NopLogger struct{}

func (NopLogger) Info(msg string, keysAndValues ...any)  {}
func (NopLogger) Error(msg string, keysAndValues ...any) {}
func (NopLogger) Debug(msg string, keysAndValues ...any) {}
