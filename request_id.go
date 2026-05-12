package sso

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/snaplink/sso/audit"
)

// requestIDBytes is the size in bytes of generated IDs (16 → 32 hex chars).
const requestIDBytes = 16

// tracer is the package-level helper for parsing/formatting W3C traceparent.
// Stateless — safe to share.
var tracer = audit.NewTracer()

// TracingMiddleware combines two correlation strategies:
//
//   - X-Request-Id (one HTTP hop) — preserve incoming, otherwise generate.
//   - W3C Traceparent (full call chain) — preserve incoming trace, but
//     create a fresh span here so downstream calls see us as the parent.
//
// Both flow back to the caller via response headers and into the request
// header so audit helpers (auditEventFromRequest) can pick them up without
// extra plumbing.
func TracingMiddleware() MiddlewareFunc {
	return func(ctx HandlerContext) {
		r := ctx.Request()
		w := ctx.ResponseWriter()

		// Request ID (single hop).
		reqID := r.Header.Get(HeaderRequestID)
		if reqID == "" {
			reqID = newRequestID()
			r.Header.Set(HeaderRequestID, reqID)
		}
		w.Header().Set(HeaderRequestID, reqID)

		// Trace context (full chain).
		var parent audit.TraceContext
		if h := r.Header.Get(HeaderTraceparent); h != "" {
			if tc, err := tracer.ParseTraceparent(h); err == nil {
				parent = tc
			}
		}
		current := tracer.StartChild(parent)
		r.Header.Set(HeaderTraceparent, tracer.FormatTraceparent(current))
		w.Header().Set(HeaderTraceparent, tracer.FormatTraceparent(current))
		if current.ParentSpanID != "" {
			r.Header.Set(HeaderParentSpanID, current.ParentSpanID)
		}
	}
}

// RequestIDMiddleware is kept as a back-compat alias of TracingMiddleware.
// New code should call TracingMiddleware directly.
func RequestIDMiddleware() MiddlewareFunc { return TracingMiddleware() }

func newRequestID() string {
	var b [requestIDBytes]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
