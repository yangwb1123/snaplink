package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// newSlogLoggerToBuf mirrors newSlogLogger but writes to buf instead of
// os.Stdout, so a test can inspect what got emitted at each level. No
// mocks — the real construction path, just a different io.Writer.
func newSlogLoggerToBuf(buf *bytes.Buffer, level string) *slogLogger {
	var levelVar slog.LevelVar
	levelVar.Set(parseLogLevel(level))
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: &levelVar})
	return &slogLogger{inner: slog.New(h), level: &levelVar}
}

func TestParseLogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"error": slog.LevelError,
		"":      slog.LevelInfo,
		"bogus": slog.LevelInfo,
		"DEBUG": slog.LevelInfo, // case-sensitive, matching config.validate()'s ToLower normalization happening upstream
	}
	for in, want := range cases {
		if got := parseLogLevel(in); got != want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNewSlogLogger_DebugSuppressedAtInfoLevel(t *testing.T) {
	var buf bytes.Buffer
	l := newSlogLoggerToBuf(&buf, "info")
	l.Debug("should not appear")
	if buf.Len() != 0 {
		t.Fatalf("expected no output at info level for a Debug call, got %q", buf.String())
	}
}

func TestSlogLogger_SetLevel_LiveChangesVerbosity(t *testing.T) {
	var buf bytes.Buffer
	l := newSlogLoggerToBuf(&buf, "info")

	l.Debug("first debug")
	if buf.Len() != 0 {
		t.Fatalf("expected debug suppressed before SetLevel, got %q", buf.String())
	}

	// This is the crux of the hot-reload story: SetLevel changes verbosity
	// on the ALREADY-CONSTRUCTED logger — no new handler, no restart.
	l.SetLevel("debug")
	l.Debug("second debug")

	if !strings.Contains(buf.String(), "second debug") {
		t.Fatalf("expected debug output after SetLevel(\"debug\"), got %q", buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("decode emitted record: %v (raw=%q)", err, buf.String())
	}
	if rec["msg"] != "second debug" {
		t.Errorf("msg = %v, want %q", rec["msg"], "second debug")
	}
}

func TestSlogLogger_SetLevel_CanRaiseBackToError(t *testing.T) {
	var buf bytes.Buffer
	l := newSlogLoggerToBuf(&buf, "debug")

	l.SetLevel("error")
	l.Info("suppressed after raising the level")
	if buf.Len() != 0 {
		t.Fatalf("expected info suppressed after SetLevel(\"error\"), got %q", buf.String())
	}
	l.Error("still visible")
	if !strings.Contains(buf.String(), "still visible") {
		t.Fatalf("expected error output to remain visible, got %q", buf.String())
	}
}
