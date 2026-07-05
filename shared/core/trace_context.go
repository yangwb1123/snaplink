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

// cspNonceContextKey is the context key for the request's per-request
// Content-Security-Policy nonce.
type cspNonceContextKey struct{}

// WithCSPNonce returns a context carrying the given per-request CSP nonce.
// Set by the security-headers middleware (internal/handler.SecurityHeaders)
// BEFORE the request reaches any handler, so the same value that goes into
// the CSP header's script-src 'nonce-...' directive is also readable by an
// HTML-rendering handler further down the stack.
func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, cspNonceContextKey{}, nonce)
}

// CSPNonceFromContext returns the CSP nonce stored in the context by the
// security-headers middleware, or empty string when security headers are not
// enabled for this request (e.g. WithSecurityHeaders was never called, or the
// request reached a handler outside that middleware's scope). Callers — e.g.
// the OIDC form_post / JARM auto-submit page renderers — use this to stamp a
// matching nonce="..." attribute on an inline <script>, and MUST tolerate an
// empty return (omit the attribute) since the feature is opt-in.
func CSPNonceFromContext(ctx context.Context) string {
	nonce, _ := ctx.Value(cspNonceContextKey{}).(string)
	return nonce
}
