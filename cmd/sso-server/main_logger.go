package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/snaplink/sso/shared/spi"
)

func newSlogLogger(level string) *slogLogger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return &slogLogger{inner: slog.New(h)}
}

func (l *slogLogger) Info(msg string, kv ...any)  { l.inner.Info(msg, kv...) }
func (l *slogLogger) Error(msg string, kv ...any) { l.inner.Error(msg, kv...) }
func (l *slogLogger) Debug(msg string, kv ...any) { l.inner.Debug(msg, kv...) }

// slogLogger implements spi.ContextLogger: the *Ctx variants append the
// W3C trace_id the SDK stamped onto ctx (parsed from the request's
// traceparent — the same id that lands on audit Event.TraceID), so ops
// log lines join to traces + audit. Absent trace → no field emitted.
// trace_id is LOG-ONLY; it never touches a wire response.
var _ spi.ContextLogger = (*slogLogger)(nil)

func (l *slogLogger) InfoCtx(ctx context.Context, msg string, kv ...any) {
	l.inner.Info(msg, withTraceID(ctx, kv)...)
}

func (l *slogLogger) ErrorCtx(ctx context.Context, msg string, kv ...any) {
	l.inner.Error(msg, withTraceID(ctx, kv)...)
}

func (l *slogLogger) DebugCtx(ctx context.Context, msg string, kv ...any) {
	l.inner.Debug(msg, withTraceID(ctx, kv)...)
}

// withTraceID appends a trace_id key/value to kv when ctx carries a W3C
// trace id, otherwise returns kv unchanged.
func withTraceID(ctx context.Context, kv []any) []any {
	if tid := spi.TraceIDFromContext(ctx); tid != "" {
		return append(kv, slog.String("trace_id", tid))
	}
	return kv
}
