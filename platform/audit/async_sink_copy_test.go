package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

type captureAsyncSink struct {
	received chan *audit.Event
	release  chan struct{}
}

func (s *captureAsyncSink) Record(_ context.Context, event *audit.Event) error {
	s.received <- event
	<-s.release
	return nil
}

func (s *captureAsyncSink) Get(_ context.Context, _ string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}

func (s *captureAsyncSink) Query(_ context.Context, _ audit.Query) ([]*audit.Event, error) {
	return nil, nil
}

func TestAsyncSink_SnapshotsAcceptedEventBeforeDelivery(t *testing.T) {
	t.Parallel()
	inner := &captureAsyncSink{received: make(chan *audit.Event, 1), release: make(chan struct{})}
	async := audit.NewAsyncSink(inner, audit.WithAsyncBuffer(1))
	async.Start()

	input := &audit.Event{Type: audit.EventLogin, Metadata: map[string]string{"role": "reader"}}
	if err := async.Record(context.Background(), input); err != nil {
		t.Fatalf("Record: %v", err)
	}
	select {
	case received := <-inner.received:
		input.Metadata["role"] = "admin"
		input.Metadata["changed"] = "caller"
		close(inner.release)
		if err := async.Close(context.Background()); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if received.Metadata["role"] != "reader" || len(received.Metadata) != 1 {
			t.Fatalf("queued event aliased caller metadata: %v", received.Metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not receive event")
	}
}

var _ audit.Sink = (*captureAsyncSink)(nil)
