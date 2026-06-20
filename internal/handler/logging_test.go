package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

const sampleTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"

// validTraceparent is a W3C traceparent carrying sampleTraceID.
const validTraceparent = "00-" + sampleTraceID + "-00f067aa0ba902b7-01"

// TestTraceIDFromRequest locks extraction of the W3C TraceID from the
// traceparent header, returning "" for absent or malformed headers (so a bad
// header degrades to "no trace id" rather than erroring out the log path).
func TestTraceIDFromRequest(t *testing.T) {
	cases := []struct {
		name        string
		traceparent string
		want        string
	}{
		{"valid traceparent", validTraceparent, sampleTraceID},
		{"absent header", "", ""},
		{"malformed header", "not-a-traceparent", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			if c.traceparent != "" {
				r.Header.Set(core.HeaderTraceparent, c.traceparent)
			}
			if got := TraceIDFromRequest(r); got != c.want {
				t.Fatalf("TraceIDFromRequest = %q, want %q", got, c.want)
			}
		})
	}
}

// TestTraceContext verifies the request trace id is threaded into the returned
// context so a ContextLogger can correlate log lines.
func TestTraceContext(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set(core.HeaderTraceparent, validTraceparent)
	ctx := TraceContext(r)
	if got := spi.TraceIDFromContext(ctx); got != sampleTraceID {
		t.Fatalf("trace id in context = %q, want %q", got, sampleTraceID)
	}

	// Absent header => empty trace id => context carries nothing.
	r2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	if got := spi.TraceIDFromContext(TraceContext(r2)); got != "" {
		t.Fatalf("expected empty trace id for header-less request, got %q", got)
	}
}

// captureLogger is a real spi.ContextLogger used to assert LogErrorCtx routes
// through the context-aware path with the request's trace id. It is a test
// double for the Logger SPI, not a mock of a repo concern.
type captureLogger struct {
	lastMsg     string
	lastTraceID string
	ctxUsed     bool
}

func (l *captureLogger) Debug(msg string, _ ...any) {}
func (l *captureLogger) Info(msg string, _ ...any)  {}
func (l *captureLogger) Error(msg string, _ ...any) { l.lastMsg = msg }

func (l *captureLogger) DebugCtx(_ context.Context, _ string, _ ...any) {}
func (l *captureLogger) InfoCtx(_ context.Context, _ string, _ ...any)  {}
func (l *captureLogger) ErrorCtx(ctx context.Context, msg string, _ ...any) {
	l.ctxUsed = true
	l.lastMsg = msg
	l.lastTraceID = spi.TraceIDFromContext(ctx)
}

// plainLogger implements only spi.Logger (no *Ctx methods) to exercise the
// non-ContextLogger fallback branch of LogErrorCtx.
type plainLogger struct {
	lastMsg string
}

func (l *plainLogger) Debug(msg string, _ ...any) {}
func (l *plainLogger) Info(msg string, _ ...any)  {}
func (l *plainLogger) Error(msg string, _ ...any) { l.lastMsg = msg }

// TestLogErrorCtx_ContextLogger verifies a ContextLogger is routed through the
// *Ctx path carrying the request's trace id.
func TestLogErrorCtx_ContextLogger(t *testing.T) {
	lg := &captureLogger{}
	d := &ServerDeps{Logger: lg}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set(core.HeaderTraceparent, validTraceparent)
	ctx := core.NewContext(httptest.NewRecorder(), r)
	LogErrorCtx(d, ctx, "boom")
	if !lg.ctxUsed {
		t.Fatal("expected ErrorCtx (context path) to be used for a ContextLogger")
	}
	if lg.lastMsg != "boom" {
		t.Fatalf("lastMsg = %q, want boom", lg.lastMsg)
	}
	if lg.lastTraceID != sampleTraceID {
		t.Fatalf("trace id not threaded: got %q, want %q", lg.lastTraceID, sampleTraceID)
	}
}

// TestLogErrorCtx_PlainLogger verifies a logger that does NOT implement
// spi.ContextLogger falls back to plain Error.
func TestLogErrorCtx_PlainLogger(t *testing.T) {
	lg := &plainLogger{}
	d := &ServerDeps{Logger: lg}
	ctx := core.NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	LogErrorCtx(d, ctx, "boom")
	if lg.lastMsg != "boom" {
		t.Fatalf("plain logger Error not called; got %q", lg.lastMsg)
	}
}

var (
	_ spi.Logger        = (*plainLogger)(nil)
	_ spi.ContextLogger = (*captureLogger)(nil)
)
