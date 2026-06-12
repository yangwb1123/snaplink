package sqlite

import (
	"context"
	"testing"

	"github.com/snaplink/sso/audit"
)

func TestSinkRecordBatch(t *testing.T) {
	sink := newTestSink(t)

	events := []*audit.Event{
		{Type: "t1", ActorID: "u1"},
		{Type: "t2", ActorID: "u2"},
		{Type: "t3", ActorID: "u3"},
	}
	if err := sink.RecordBatch(context.Background(), events); err != nil {
		t.Fatalf("RecordBatch: %v", err)
	}

	got, err := sink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("got %d events, want 3", len(got))
	}
}

func TestSinkRecordBatch_Empty(t *testing.T) {
	sink := newTestSink(t)

	if err := sink.RecordBatch(context.Background(), nil); err != nil {
		t.Errorf("RecordBatch(nil): %v", err)
	}
}

func TestBatchSink_InterfaceGuard(t *testing.T) {
	var _ audit.BatchSink = (*Sink)(nil)
}
