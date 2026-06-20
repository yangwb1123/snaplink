package audit_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

// stubSink is a Sink double whose behavior tests configure. Only Record is
// exercised by the recorder tests; Get/Query are unused here.
type stubSink struct {
	mu        sync.Mutex
	recorded  []*audit.Event
	recordErr error
}

func (s *stubSink) Record(_ context.Context, e *audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recordErr != nil {
		return s.recordErr
	}
	s.recorded = append(s.recorded, e)
	return nil
}

func (s *stubSink) Get(_ context.Context, _ string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}

func (s *stubSink) Query(_ context.Context, _ audit.Query) ([]*audit.Event, error) {
	return nil, nil
}

func (s *stubSink) snapshot() []*audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*audit.Event, len(s.recorded))
	copy(out, s.recorded)
	return out
}

func TestRecorder_RecordPersistsEvent(t *testing.T) {
	s := &stubSink{}
	r := audit.New(s)
	r.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	got := s.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected 1 recorded event, got %d", len(got))
	}
	if got[0].Type != audit.EventLogin {
		t.Errorf("type = %q, want %q", got[0].Type, audit.EventLogin)
	}
}

func TestRecorder_FillsZeroTimestampFromClock(t *testing.T) {
	frozen := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	s := &stubSink{}
	r := audit.New(s, audit.WithClock(func() time.Time { return frozen }))

	r.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	got := s.snapshot()
	if !got[0].Timestamp.Equal(frozen) {
		t.Fatalf("timestamp = %v, want %v", got[0].Timestamp, frozen)
	}
}

func TestRecorder_PreservesNonZeroTimestamp(t *testing.T) {
	preset := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	frozen := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	s := &stubSink{}
	r := audit.New(s, audit.WithClock(func() time.Time { return frozen }))

	r.Record(context.Background(), &audit.Event{Type: audit.EventLogin, Timestamp: preset})

	got := s.snapshot()
	if !got[0].Timestamp.Equal(preset) {
		t.Fatalf("timestamp = %v, want preset %v (clock should not override)", got[0].Timestamp, preset)
	}
}

func TestRecorder_RoutesSinkErrorToHandler(t *testing.T) {
	sinkErr := errors.New("boom")
	s := &stubSink{recordErr: sinkErr}

	var seen error
	r := audit.New(s, audit.WithErrorHandler(func(err error) { seen = err }))
	r.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	if !errors.Is(seen, sinkErr) {
		t.Fatalf("handler got %v, want %v", seen, sinkErr)
	}
}

func TestRecorder_SwallowsSinkErrorWhenNoHandler(t *testing.T) {
	s := &stubSink{recordErr: errors.New("boom")}
	r := audit.New(s)
	// Must not panic and must not propagate the error.
	r.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
}

func TestRecorder_NilSafety(t *testing.T) {
	// nil recorder
	var r *audit.Recorder
	r.Record(context.Background(), &audit.Event{Type: audit.EventLogin}) // must not panic

	// nil sink: New does not guard against this, but Record handles it.
	r2 := audit.New(nil)
	r2.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	// nil event
	s := &stubSink{}
	r3 := audit.New(s)
	r3.Record(context.Background(), nil)
	if got := s.snapshot(); len(got) != 0 {
		t.Fatalf("nil event should not be recorded, got %v", got)
	}
}

func TestRecorder_SinkAccessor(t *testing.T) {
	s := &stubSink{}
	r := audit.New(s)
	if r.Sink() != s {
		t.Fatal("Sink() should return the underlying sink instance")
	}
}

func TestRecorder_DefaultClockIsRealTime(t *testing.T) {
	// Smoke test: without WithClock, the timestamp should be close to time.Now.
	s := &stubSink{}
	r := audit.New(s)
	before := time.Now()
	r.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	after := time.Now()

	got := s.snapshot()[0].Timestamp
	if got.Before(before) || got.After(after) {
		t.Fatalf("timestamp %v not in [%v, %v]", got, before, after)
	}
}
