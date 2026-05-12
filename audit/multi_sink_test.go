package audit_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/audit"
)

func TestMultiSink_FansOutToAllSinks(t *testing.T) {
	var buf bytes.Buffer
	mem := audit.NewMemorySink(10)
	wr := audit.NewWriterSink(&buf)
	multi := audit.NewMultiSink(mem, wr)

	if err := multi.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if mem.Len() != 1 {
		t.Errorf("memory sink should have 1 event, got %d", mem.Len())
	}
	if buf.Len() == 0 {
		t.Errorf("writer sink should have written something")
	}
}

func TestMultiSink_GetSkipsWriteOnlySinks(t *testing.T) {
	wr := audit.NewWriterSink(&bytes.Buffer{})
	mem := audit.NewMemorySink(10)
	// Writer-only first; readback sink second. MultiSink must skip the first.
	multi := audit.NewMultiSink(wr, mem)

	e := &audit.Event{Type: audit.EventLogin}
	_ = multi.Record(context.Background(), e)

	got, err := multi.Get(context.Background(), e.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != e.ID {
		t.Errorf("Get returned wrong event: %+v", got)
	}
}

func TestMultiSink_QueryDelegatesToFirstReadableSink(t *testing.T) {
	wr := audit.NewWriterSink(&bytes.Buffer{})
	mem := audit.NewMemorySink(10)
	multi := audit.NewMultiSink(wr, mem)

	_ = multi.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "alice"})
	_ = multi.Record(context.Background(), &audit.Event{Type: audit.EventLogout, ActorID: "alice"})

	out, err := multi.Query(context.Background(), audit.Query{Type: audit.EventLogin})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("Query: got %d, want 1", len(out))
	}
}

// errorSink unconditionally fails Record. Used to verify error aggregation.
type errorSink struct{ err error }

func (e errorSink) Record(_ context.Context, _ *audit.Event) error { return e.err }
func (errorSink) Get(_ context.Context, _ string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}
func (errorSink) Query(_ context.Context, _ audit.Query) ([]*audit.Event, error) { return nil, nil }

func TestMultiSink_JoinsRecordErrors(t *testing.T) {
	a := errors.New("a failed")
	b := errors.New("b failed")
	multi := audit.NewMultiSink(errorSink{err: a}, errorSink{err: b})

	err := multi.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if err == nil {
		t.Fatal("expected joined error")
	}
	if !errors.Is(err, a) || !errors.Is(err, b) {
		t.Fatalf("joined error should match both children; got %v", err)
	}
}

func TestMultiSink_AllWriteOnlyQueryStillSurfacesWriteOnlyErr(t *testing.T) {
	multi := audit.NewMultiSink(audit.NewWriterSink(&bytes.Buffer{}))
	if _, err := multi.Query(context.Background(), audit.Query{}); !errors.Is(err, audit.ErrSinkWriteOnly) {
		t.Fatalf("expected ErrSinkWriteOnly, got %v", err)
	}
}

func TestMultiSink_AllWriteOnlyGetReturnsEventNotFound(t *testing.T) {
	// When every sink is write-only, the loop falls through and we should
	// see ErrEventNotFound — not the write-only sentinel.
	multi := audit.NewMultiSink(audit.NewWriterSink(&bytes.Buffer{}))
	if _, err := multi.Get(context.Background(), "anything"); !errors.Is(err, audit.ErrEventNotFound) {
		t.Fatalf("expected ErrEventNotFound, got %v", err)
	}
}
