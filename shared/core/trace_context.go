package core

import "context"

// traceIDContextKey is the context key for the request's W3C trace ID.
type traceIDContextKey struct{}

// WithTraceID returns a context carrying the given trace ID.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDContextKey{}, traceID)
}

// TraceIDFromContext returns the trace ID stored in the context by the
// Tracing middleware, or empty string when tracing is not active.
func TraceIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(traceIDContextKey{}).(string)
	return id
}
