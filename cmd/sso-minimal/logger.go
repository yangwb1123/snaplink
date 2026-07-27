package main

import (
	"context"
	"io"
	"log/slog"

	"github.com/yangwb1123/snaplink/shared/spi"
)

type jsonLogger struct {
	inner *slog.Logger
}

func newJSONLogger(w io.Writer) *jsonLogger {
	return &jsonLogger{
		inner: slog.New(slog.NewJSONHandler(w, nil)),
	}
}

func (l *jsonLogger) Info(msg string, values ...any) {
	l.inner.Info(msg, values...)
}

func (l *jsonLogger) Error(msg string, values ...any) {
	l.inner.Error(msg, values...)
}

func (l *jsonLogger) Debug(msg string, values ...any) {
	l.inner.Debug(msg, values...)
}

func (l *jsonLogger) InfoCtx(ctx context.Context, msg string, values ...any) {
	l.inner.InfoContext(ctx, msg, withTraceID(ctx, values)...)
}

func (l *jsonLogger) ErrorCtx(ctx context.Context, msg string, values ...any) {
	l.inner.ErrorContext(ctx, msg, withTraceID(ctx, values)...)
}

func (l *jsonLogger) DebugCtx(ctx context.Context, msg string, values ...any) {
	l.inner.DebugContext(ctx, msg, withTraceID(ctx, values)...)
}

func withTraceID(ctx context.Context, values []any) []any {
	if traceID := spi.TraceIDFromContext(ctx); traceID != "" {
		return append(values, slog.String("trace_id", traceID))
	}
	return values
}

var _ spi.ContextLogger = (*jsonLogger)(nil)
