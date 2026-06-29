package spi_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/shared/spi"
)

// capturingLogger is a plain spi.Logger (NOT a ContextLogger) used to prove
// the SDK fallback path keeps working — no panic, no trace_id, just the
// base call. No mocks per §8: this is a real in-memory impl.
type capturingLogger struct {
	lastMsg string
	lastKV  []any
	calls   int
}

func (l *capturingLogger) Info(msg string, kv ...any)  { l.record(msg, kv) }
func (l *capturingLogger) Error(msg string, kv ...any) { l.record(msg, kv) }
func (l *capturingLogger) Debug(msg string, kv ...any) { l.record(msg, kv) }

func (l *capturingLogger) record(msg string, kv []any) {
	l.lastMsg = msg
	l.lastKV = kv
	l.calls++
}

// ctxCapturingLogger additionally implements ContextLogger and records the
// trace id it read off the context, proving the *Ctx path reaches the id.
type ctxCapturingLogger struct {
	capturingLogger
	lastTraceID string
}

func (l *ctxCapturingLogger) ErrorCtx(ctx context.Context, msg string, kv ...any) {
	l.lastTraceID = spi.TraceIDFromContext(ctx)
	l.Error(msg, kv...)
}
func (l *ctxCapturingLogger) InfoCtx(ctx context.Context, msg string, kv ...any) {
	l.lastTraceID = spi.TraceIDFromContext(ctx)
	l.Info(msg, kv...)
}
func (l *ctxCapturingLogger) DebugCtx(ctx context.Context, msg string, kv ...any) {
	l.lastTraceID = spi.TraceIDFromContext(ctx)
	l.Debug(msg, kv...)
}

func TestPlainLoggerIsNotContextLogger(t *testing.T) {
	t.Parallel()
	var l spi.Logger = &capturingLogger{}
	if _, ok := l.(spi.ContextLogger); ok {
		t.Fatal("plain capturingLogger must NOT satisfy spi.ContextLogger")
	}
	// The fallback must keep the base Logger working without panic.
	l.Error("boom", "k", "v")
	if got := l.(*capturingLogger).lastMsg; got != "boom" {
		t.Fatalf("Error not recorded: got %q", got)
	}
}

func TestContextLoggerReadsTraceID(t *testing.T) {
	t.Parallel()
	var l spi.Logger = &ctxCapturingLogger{}
	cl, ok := l.(spi.ContextLogger)
	if !ok {
		t.Fatal("ctxCapturingLogger must satisfy spi.ContextLogger")
	}

	const tid = "0af7651916cd43dd8448eb211c80319c"
	ctx := spi.ContextWithTraceID(context.Background(), tid)
	cl.ErrorCtx(ctx, "boom", "k", "v")
	if got := l.(*ctxCapturingLogger).lastTraceID; got != tid {
		t.Fatalf("trace id not propagated: got %q want %q", got, tid)
	}
}

func TestContextWithTraceIDEmptyIsNoOp(t *testing.T) {
	t.Parallel()
	base := context.Background()
	// Empty tid must return the SAME context (no value stashed) so the
	// logger omits the field.
	if got := spi.ContextWithTraceID(base, ""); got != base {
		t.Fatal("ContextWithTraceID with empty tid must return ctx unchanged")
	}
	if got := spi.TraceIDFromContext(base); got != "" {
		t.Fatalf("TraceIDFromContext on bare ctx must be empty, got %q", got)
	}
	if got := spi.TraceIDFromContext(nil); got != "" { //nolint:staticcheck // nil ctx is intentional
		t.Fatalf("TraceIDFromContext(nil) must be empty, got %q", got)
	}
}
