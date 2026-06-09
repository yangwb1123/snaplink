package sso

import (
	"context"
	"net/http"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/spi"
)

// logErrorCtx routes an Error log line through the wired logger, attaching
// the request's W3C trace id when the logger implements [spi.ContextLogger]
// (so ops logs can be joined to traces + audit). It is a drop-in for
// `s.logger.Error(msg, kv...)` at the highest-value auth log sites that
// already hold a [core.HandlerContext].
//
// When the logger does NOT implement ContextLogger, this falls back to the
// plain [spi.Logger.Error] — byte-identical to the old call, no trace id.
// The trace id is LOG-ONLY: this never touches any wire response.
func (s *Server) logErrorCtx(ctx core.HandlerContext, msg string, kv ...any) {
	cl, ok := s.logger.(spi.ContextLogger)
	if !ok {
		s.logger.Error(msg, kv...)
		return
	}
	cl.ErrorCtx(s.traceContext(ctx), msg, kv...)
}

// traceContext derives a context.Context carrying the request's W3C trace
// id (parsed from the traceparent header the Tracing middleware stamped —
// the SAME source audit.EventFromRequest reads). When no valid trace is
// present the request context is returned unchanged, so the logger omits
// the field.
func (s *Server) traceContext(ctx core.HandlerContext) context.Context {
	r := ctx.Request()
	base := r.Context()
	tid := traceIDFromRequest(r)
	return spi.ContextWithTraceID(base, tid)
}

// traceIDFromRequest extracts the W3C TraceID from the request's
// traceparent header, or "" when absent/malformed.
func traceIDFromRequest(r *http.Request) string {
	tp := r.Header.Get(HeaderTraceparent)
	if tp == "" {
		return ""
	}
	tc, err := tracer.ParseTraceparent(tp)
	if err != nil {
		return ""
	}
	return tc.TraceID
}
