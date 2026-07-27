package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/configaudit"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStore_SatisfiesStoreInterface(t *testing.T) {
	var _ configaudit.Store = (*Store)(nil)
}

func TestStore_RecordAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	entry := configaudit.Entry{
		Actor:      "alice",
		TenantID:   "t1",
		Resource:   "client",
		ResourceID: "c1",
		Patch:      []configaudit.Op{{Op: "replace", Path: "/name", Value: "new-name"}},
		Reason:     "admin_client_updated",
	}
	if err := s.Record(ctx, entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries, err := s.List(ctx, configaudit.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	got := entries[0]
	if got.ID == "" {
		t.Errorf("Record must assign an ID when left empty")
	}
	if got.Actor != "alice" || got.TenantID != "t1" || got.Resource != "client" || got.ResourceID != "c1" {
		t.Errorf("round-tripped entry mismatch: %+v", got)
	}
	if len(got.Patch) != 1 || got.Patch[0].Path != "/name" || got.Patch[0].Value != "new-name" {
		t.Errorf("patch did not round-trip through the JSON column: %+v", got.Patch)
	}
}

func TestStore_FilterByResourceAndSince(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old := time.Now().Add(-2 * time.Hour)
	_ = s.Record(ctx, configaudit.Entry{Resource: "client", ResourceID: "old", RecordedAt: old})
	_ = s.Record(ctx, configaudit.Entry{Resource: "tenant", ResourceID: "t1", RecordedAt: time.Now()})
	_ = s.Record(ctx, configaudit.Entry{Resource: "client", ResourceID: "new", RecordedAt: time.Now()})

	entries, err := s.List(ctx, configaudit.Filter{Resource: "client", Since: time.Now().Add(-1 * time.Hour)})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].ResourceID != "new" {
		t.Fatalf("expected only the recent client entry, got %+v", entries)
	}
}

func TestStore_ClosedReturnsError(t *testing.T) {
	s := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Record(context.Background(), configaudit.Entry{Resource: "client"}); err == nil {
		t.Errorf("Record on a closed store must error")
	}
	if _, err := s.List(context.Background(), configaudit.Filter{}); err == nil {
		t.Errorf("List on a closed store must error")
	}
}
