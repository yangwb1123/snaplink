package handler

import (
	"context"
	"net/http"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

var tracer = audit.NewTracer()

// LogErrorCtx routes an Error log line through the wired logger, attaching
// the request's W3C trace id when the logger implements spi.ContextLogger.
func LogErrorCtx(d *ServerDeps, ctx HandlerContext, msg string, kv ...any) {
	cl, ok := d.Logger.(spi.ContextLogger)
	if !ok {
		d.Logger.Error(msg, kv...)
		return
	}
	cl.ErrorCtx(traceContext(ctx), msg, kv...)
}

// traceContext derives a context.Context carrying the request's W3C trace id.
func traceContext(ctx HandlerContext) context.Context {
	r := ctx.Request()
	base := r.Context()
	tid := TraceIDFromRequest(r)
	return spi.ContextWithTraceID(base, tid)
}

// TraceContext derives a context.Context carrying the W3C trace id from
// the http.Request. It extracts the traceparent header from the request
// and embeds the trace ID into the returned context.
func TraceContext(r *http.Request) context.Context {
	base := r.Context()
	tid := TraceIDFromRequest(r)
	return spi.ContextWithTraceID(base, tid)
}

// TraceIDFromRequest extracts the W3C TraceID from the request's
// traceparent header, or "" when absent/malformed.
func TraceIDFromRequest(r *http.Request) string {
	tp := r.Header.Get(core.HeaderTraceparent)
	if tp == "" {
		return ""
	}
	tc, err := tracer.ParseTraceparent(tp)
	if err != nil {
		return ""
	}
	return tc.TraceID
}
