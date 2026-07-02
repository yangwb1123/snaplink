package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/platform/audit"
)

// recordTypes records the given event types through sink and returns the
// event types the backing MemorySink actually stored (newest-first).
func recordTypes(t *testing.T, sink audit.Sink, mem *audit.MemorySink, types ...audit.EventType) []audit.EventType {
	t.Helper()
	for _, et := range types {
		if err := sink.Record(context.Background(), &audit.Event{Type: et}); err != nil {
			t.Fatalf("Record(%s): %v", et, err)
		}
	}
	got, err := mem.Query(context.Background(), audit.Query{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	out := make([]audit.EventType, 0, len(got))
	for _, e := range got {
		out = append(out, e.Type)
	}
	return out
}

func containsType(types []audit.EventType, want audit.EventType) bool {
	for _, tp := range types {
		if tp == want {
			return true
		}
	}
	return false
}

func TestFilteringSink_ExactMatchOnlyDeliversAllowed(t *testing.T) {
	t.Parallel()
	mem := audit.NewMemorySink(64)
	sink := audit.NewFilteringSink(mem, audit.WithEventTypeFilter(string(audit.EventLogin)))

	got := recordTypes(t, sink, mem, audit.EventLogin, audit.EventLogout, audit.EventLogin)
	if len(got) != 2 {
		t.Fatalf("stored %d events want 2 (only login)", len(got))
	}
	if containsType(got, audit.EventLogout) {
		t.Fatalf("logout leaked through an exact login-only filter: %v", got)
	}
}

func TestFilteringSink_EmptyFilterIsFirehose(t *testing.T) {
	t.Parallel()
	mem := audit.NewMemorySink(64)
	// No WithEventTypeFilter option at all — empty allow-set must pass all.
	sink := audit.NewFilteringSink(mem)

	got := recordTypes(t, sink, mem, audit.EventLogin, audit.EventLogout, audit.EventTokenIssued)
	if len(got) != 3 {
		t.Fatalf("firehose stored %d events want 3", len(got))
	}
}

func TestFilteringSink_BlankEntriesAreFirehose(t *testing.T) {
	t.Parallel()
	mem := audit.NewMemorySink(64)
	// A list of only blank entries contributes nothing to the allow-set,
	// so it collapses to the firehose (matches "empty = all") rather than
	// silently dropping every event.
	sink := audit.NewFilteringSink(mem, audit.WithEventTypeFilter("", ""))

	got := recordTypes(t, sink, mem, audit.EventLogin, audit.EventLogout)
	if len(got) != 2 {
		t.Fatalf("blank-only filter stored %d events want 2 (firehose)", len(got))
	}
}

func TestFilteringSink_TrailingWildcardPrefixMatch(t *testing.T) {
	t.Parallel()
	mem := audit.NewMemorySink(64)
	sink := audit.NewFilteringSink(mem,
		audit.WithEventTypeFilter(string(audit.EventAdminClientCreated[:len("admin_")])+audit.EventTypeWildcardSuffix))

	got := recordTypes(t, sink, mem,
		audit.EventAdminClientCreated, // admin_client_created — matches admin_*
		audit.EventAdminUserDeleted,   // admin_user_deleted   — matches admin_*
		audit.EventLogin,              // login                — does not match
	)
	if len(got) != 2 {
		t.Fatalf("admin_* filter stored %d events want 2", len(got))
	}
	if containsType(got, audit.EventLogin) {
		t.Fatalf("login leaked through admin_* prefix filter: %v", got)
	}
}

func TestFilteringSink_MixedExactAndWildcard(t *testing.T) {
	t.Parallel()
	mem := audit.NewMemorySink(64)
	sink := audit.NewFilteringSink(mem, audit.WithEventTypeFilter(
		string(audit.EventLogin),
		"admin_"+audit.EventTypeWildcardSuffix,
	))

	got := recordTypes(t, sink, mem,
		audit.EventLogin,              // exact
		audit.EventAdminClientDeleted, // wildcard
		audit.EventLogout,             // neither
	)
	if len(got) != 2 {
		t.Fatalf("mixed filter stored %d events want 2", len(got))
	}
	if containsType(got, audit.EventLogout) {
		t.Fatalf("logout leaked through mixed filter: %v", got)
	}
}

func TestFilteringSink_DroppedEventIsSuccess(t *testing.T) {
	t.Parallel()
	// A dropped (filtered-out) event MUST return nil so a MultiSink
	// errors.Join stays clean — a filter is not a delivery failure.
	mem := audit.NewMemorySink(8)
	sink := audit.NewFilteringSink(mem, audit.WithEventTypeFilter(string(audit.EventLogin)))
	if err := sink.Record(context.Background(), &audit.Event{Type: audit.EventLogout}); err != nil {
		t.Fatalf("dropped event returned error: %v", err)
	}
}

func TestFilteringSink_ReadPathDelegates(t *testing.T) {
	t.Parallel()
	mem := audit.NewMemorySink(8)
	sink := audit.NewFilteringSink(mem, audit.WithEventTypeFilter(string(audit.EventLogin)))
	_ = sink.Record(context.Background(), &audit.Event{Type: audit.EventLogin})

	got, err := sink.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query delegate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Query through filter len=%d want 1", len(got))
	}
}

func TestFilteringSink_WriteOnlyInnerPropagates(t *testing.T) {
	t.Parallel()
	// Wrapping a write-only sink keeps Get/Query write-only end-to-end.
	sink := audit.NewFilteringSink(audit.NewWebhookSink("http://nope.invalid"))
	if _, err := sink.Get(context.Background(), "x"); !errors.Is(err, audit.ErrSinkWriteOnly) {
		t.Errorf("Get: expected ErrSinkWriteOnly, got %v", err)
	}
	if _, err := sink.Query(context.Background(), audit.Query{}); !errors.Is(err, audit.ErrSinkWriteOnly) {
		t.Errorf("Query: expected ErrSinkWriteOnly, got %v", err)
	}
}
