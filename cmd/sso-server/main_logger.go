package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/yangwb1123/snaplink/shared/spi"
)

func newSlogLogger(level string) *slogLogger {
	var levelVar slog.LevelVar
	levelVar.Set(parseLogLevel(level))
	// &levelVar (not a fixed slog.Level) so SetLevel below can change
	// verbosity on an already-constructed handler — HandlerOptions.Level
	// re-reads a *LevelVar on every log call.
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: &levelVar})
	return &slogLogger{inner: slog.New(h), level: &levelVar}
}

// parseLogLevel maps the config-file/flag string to a slog.Level,
// defaulting unrecognized values to Info (matching config.applyDefaults'
// own "info" default).
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// SetLevel changes the logger's live verbosity — the hook
// config/reload.Reloader calls when a SIGHUP-triggered reload finds
// logging.level changed. Safe for concurrent use: slog.LevelVar guards
// itself.
func (l *slogLogger) SetLevel(level string) {
	l.level.Set(parseLogLevel(level))
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
