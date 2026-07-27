package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
)

func TestWriterSink_RecordWritesJSONL(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	s := audit.NewWriterSink(&buf)

	events := []*audit.Event{
		{Type: audit.EventLogin, ActorID: "alice"},
		{Type: audit.EventLogout, ActorID: "alice", RequestID: "req-1"},
	}
	for _, e := range events {
		if err := s.Record(context.Background(), e); err != nil {
			t.Fatalf("Record: %v", err)
		}
		if e.ID == "" {
			t.Fatal("Record should assign ID")
		}
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d (%q)", len(lines), buf.String())
	}
	var first audit.Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("first line not valid JSON: %v", err)
	}
	if first.ActorID != "alice" || first.Type != audit.EventLogin {
		t.Fatalf("first event roundtrip mismatch: %+v", first)
	}

	var second audit.Event
	_ = json.Unmarshal([]byte(lines[1]), &second)
	if second.RequestID != "req-1" {
		t.Errorf("RequestID lost in roundtrip: %+v", second)
	}
}

func TestWriterSink_GetAndQueryReturnErrSinkWriteOnly(t *testing.T) {
	t.Parallel()
	s := audit.NewWriterSink(&bytes.Buffer{})

	if _, err := s.Get(context.Background(), "x"); !errors.Is(err, audit.ErrSinkWriteOnly) {
		t.Errorf("Get: expected ErrSinkWriteOnly, got %v", err)
	}
	if _, err := s.Query(context.Background(), audit.Query{}); !errors.Is(err, audit.ErrSinkWriteOnly) {
		t.Errorf("Query: expected ErrSinkWriteOnly, got %v", err)
	}
}

// failingWriter returns an error on every Write. Used to verify Record
// propagates io errors back to the caller.
type failingWriter struct{ err error }

func (f failingWriter) Write(_ []byte) (int, error) { return 0, f.err }

func TestWriterSink_PropagatesWriteError(t *testing.T) {
	t.Parallel()
	target := errors.New("disk full")
	s := audit.NewWriterSink(failingWriter{err: target})
	err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if !errors.Is(err, target) {
		t.Fatalf("expected disk-full error, got %v", err)
	}
}
