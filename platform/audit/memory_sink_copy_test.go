package audit_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
)

func TestMemorySink_DefensiveCopiesEvents(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(4)
	input := &audit.Event{
		ID:       "immutable-event",
		Type:     audit.EventLogin,
		Metadata: map[string]string{"role": "reader", "source": "login"},
	}
	if err := sink.Record(context.Background(), input); err != nil {
		t.Fatalf("Record: %v", err)
	}
	input.Metadata["role"] = "admin"
	input.Metadata["injected"] = "caller"

	got, err := sink.Get(context.Background(), input.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertImmutableEvent(t, got)
	got.Metadata["role"] = "returned"
	got.Metadata["deleted"] = "returned"

	results, err := sink.Query(context.Background(), audit.Query{Limit: 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Query returned %d events, want 1", len(results))
	}
	results[0].Metadata["role"] = "query"
	results[0].Metadata["query"] = "returned"

	stored, err := sink.Get(context.Background(), input.ID)
	if err != nil {
		t.Fatalf("Get after output mutation: %v", err)
	}
	assertImmutableEvent(t, stored)

	generated := &audit.Event{Type: audit.EventLogout}
	if err := sink.Record(context.Background(), generated); err != nil {
		t.Fatalf("Record generated ID: %v", err)
	}
	if generated.ID == "" {
		t.Fatal("Record did not write generated ID back to caller")
	}
}

func assertImmutableEvent(t *testing.T, event *audit.Event) {
	t.Helper()
	if event.ID != "immutable-event" || event.Type != audit.EventLogin {
		t.Fatalf("event identity changed: %+v", event)
	}
	if event.Metadata["role"] != "reader" || event.Metadata["source"] != "login" || len(event.Metadata) != 2 {
		t.Fatalf("event metadata changed: %v", event.Metadata)
	}
}
