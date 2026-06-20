package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/snaplink/sso/shared/spi"
)

// newBufSlogLogger builds a slogLogger writing JSON records into buf, so a
// test can inspect the emitted fields. Mirrors newSlogLogger but with a
// caller-supplied sink (no stdout). No mocks — the real slogLogger type.
func newBufSlogLogger(buf *bytes.Buffer) *slogLogger {
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return &slogLogger{inner: slog.New(h)}
}

func decodeRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("decode slog record: %v (raw=%q)", err, buf.String())
	}
	return rec
}

func TestSlogLoggerImplementsContextLogger(t *testing.T) {
	var _ spi.ContextLogger = newBufSlogLogger(&bytes.Buffer{})
}

func TestSlogLoggerCtxAppendsTraceID(t *testing.T) {
	var buf bytes.Buffer
	l := newBufSlogLogger(&buf)

	const tid = "0af7651916cd43dd8448eb211c80319c"
	ctx := spi.ContextWithTraceID(context.Background(), tid)
	l.ErrorCtx(ctx, "auth failed", "provider", "password")

	rec := decodeRecord(t, &buf)
	if got, ok := rec["trace_id"]; !ok || got != tid {
		t.Fatalf("trace_id not appended: got %v (present=%v) want %q", got, ok, tid)
	}
	if rec["msg"] != "auth failed" {
		t.Fatalf("msg lost: %v", rec["msg"])
	}
	if rec["provider"] != "password" {
		t.Fatalf("structured kv lost: %v", rec["provider"])
	}
}

func TestSlogLoggerCtxOmitsTraceIDWhenAbsent(t *testing.T) {
	var buf bytes.Buffer
	l := newBufSlogLogger(&buf)

	// A bare context carries no trace id — the field must be ABSENT
	// (not empty-string).
	l.ErrorCtx(context.Background(), "auth failed", "provider", "password")

	rec := decodeRecord(t, &buf)
	if _, ok := rec["trace_id"]; ok {
		t.Fatalf("trace_id must be omitted when ctx carries no trace: %v", rec["trace_id"])
	}
	if rec["msg"] != "auth failed" {
		t.Fatalf("msg lost: %v", rec["msg"])
	}
}

func TestSlogLoggerPlainCallUnchanged(t *testing.T) {
	var buf bytes.Buffer
	l := newBufSlogLogger(&buf)

	// The plain (non-Ctx) Error path must never emit a trace_id —
	// byte-identical to the pre-change behavior.
	l.Error("plain", "k", "v")

	rec := decodeRecord(t, &buf)
	if _, ok := rec["trace_id"]; ok {
		t.Fatalf("plain Error must not emit trace_id: %v", rec["trace_id"])
	}
}
