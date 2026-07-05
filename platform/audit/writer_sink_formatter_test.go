package audit_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/platform/audit"
)

// TestWriterSink_WithWriterFormatOverridesDefault proves the new
// WithWriterFormat option actually swaps the wire format — separate from
// writer_sink_test.go, which is left UNMODIFIED to keep proving the
// zero-option default stays byte-identical JSONL.
func TestWriterSink_WithWriterFormatOverridesDefault(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	custom := func(e *audit.Event) ([]byte, error) { return []byte("custom:" + string(e.Type)), nil }
	s := audit.NewWriterSink(&buf, audit.WithWriterFormat(custom))

	if err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := buf.String(); got != "custom:login\n" {
		t.Errorf("got %q, want %q", got, "custom:login\n")
	}
}

// TestWriterSink_FormatterErrorPropagates proves a Formatter error short-
// circuits Record before any bytes reach the writer.
func TestWriterSink_FormatterErrorPropagates(t *testing.T) {
	t.Parallel()
	target := errors.New("format boom")
	var buf bytes.Buffer
	failing := func(*audit.Event) ([]byte, error) { return nil, target }
	s := audit.NewWriterSink(&buf, audit.WithWriterFormat(failing))

	err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if !errors.Is(err, target) {
		t.Fatalf("expected format error, got %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no bytes written on formatter error, got %q", buf.String())
	}
}

// TestWriterSink_CEFOCSFSyslogAreDropInFormatters proves the three new
// constructors are just WriterSink + WithWriterFormat under the hood —
// each produces a non-empty, differently-shaped line for the same Event.
func TestWriterSink_CEFOCSFSyslogAreDropInFormatters(t *testing.T) {
	t.Parallel()
	e := &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess}

	var cefBuf, ocsfBuf, syslogBuf bytes.Buffer
	sinks := []*audit.WriterSink{
		audit.NewCEFSink(&cefBuf, "Snaplink", "SSO", "1.0"),
		audit.NewOCSFSink(&ocsfBuf),
		audit.NewSyslogSink(&syslogBuf, 10, "host", "app", nil),
	}
	for _, s := range sinks {
		if err := s.Record(context.Background(), e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if cefBuf.Len() == 0 || ocsfBuf.Len() == 0 || syslogBuf.Len() == 0 {
		t.Fatal("expected all three formatters to produce non-empty output")
	}
	if cefBuf.String() == ocsfBuf.String() || cefBuf.String() == syslogBuf.String() {
		t.Error("expected CEF/OCSF/syslog to produce differently-shaped output")
	}
}
