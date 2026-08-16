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

// --- configaudit.Store apply/rollback suite (mirrors MemoryStore's) ---

func TestStore_Applied_EmptyReturnsErr(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Applied(context.Background()); err != configaudit.ErrNoAppliedVersion {
		t.Fatalf("Applied on an empty store = %v, want ErrNoAppliedVersion", err)
	}
}

func TestStore_Apply_RoundTripsBaselineAndHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	v1, err := s.Apply(ctx, configaudit.AppliedVersion{
		Actor: "a", Digest: "d1", Reason: "r1", Snapshot: map[string]any{"name": "sso-1", "db_dsn": "secret-1"},
	})
	if err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if v1.ID == "" || v1.AppliedAt.IsZero() || v1.PrevID != "" {
		t.Errorf("first version must be ID/AppliedAt-assigned with no prev: %+v", v1)
	}
	v2, err := s.Apply(ctx, configaudit.AppliedVersion{
		Actor: "b", Digest: "d2", Reason: "r2", Snapshot: map[string]any{"name": "sso-2", "db_dsn": "secret-2"},
	})
	if err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if v2.PrevID != v1.ID {
		t.Errorf("second version must link prev = %s, got %q", v1.ID, v2.PrevID)
	}

	got, err := s.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if got.ID != v2.ID || got.Snapshot["name"] != "sso-2" || got.Actor != "b" || got.Digest != "d2" {
		t.Errorf("Applied must round-trip the latest version, got %+v", got)
	}

	entries, err := s.List(ctx, configaudit.Filter{Resource: "config"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 || entries[0].ResourceID != v2.ID {
		t.Fatalf("expected 2 config entries newest-first, got %+v", entries)
	}
	// Redacted patch only: the secret leaf must never surface in history.
	for _, e := range entries {
		for _, op := range e.Patch {
			if op.Path == "/db_dsn" && op.Value != "***" {
				t.Errorf("history patch leaks a secret: %+v", e.Patch)
			}
		}
	}
}

func TestStore_Rollback_RestoresPreviousVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, _ = s.Apply(ctx, configaudit.AppliedVersion{Actor: "a", Digest: "d1", Snapshot: map[string]any{"rate_limit": float64(10)}})
	v2, _ := s.Apply(ctx, configaudit.AppliedVersion{Actor: "b", Digest: "d2", Snapshot: map[string]any{"rate_limit": float64(40)}})

	v3, err := s.Rollback(ctx, "c", "revert")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if v3.PrevID != v2.ID || v3.Snapshot["rate_limit"] != float64(10) {
		t.Errorf("rollback must link v2 and restore v1's snapshot, got %+v", v3)
	}
	got, err := s.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if got.ID != v3.ID {
		t.Errorf("Applied after rollback = %s, want %s", got.ID, v3.ID)
	}
	if entries, _ := s.List(ctx, configaudit.Filter{Resource: "config"}); len(entries) != 3 {
		t.Errorf("expected 3 config entries (2 applies + 1 rollback), got %d", len(entries))
	}
}

func TestStore_Rollback_NoPreviousReturnsErr(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.Rollback(ctx, "a", "r"); err != configaudit.ErrNoAppliedVersion {
		t.Errorf("Rollback on empty store = %v, want ErrNoAppliedVersion", err)
	}
	_, _ = s.Apply(ctx, configaudit.AppliedVersion{Actor: "a", Digest: "d1", Snapshot: map[string]any{"a": 1}})
	if _, err := s.Rollback(ctx, "a", "r"); err != configaudit.ErrNoAppliedVersion {
		t.Errorf("Rollback with a single version = %v, want ErrNoAppliedVersion", err)
	}
}

func TestStore_Apply_Rollback_TransactionalPairOnClosedStore(t *testing.T) {
	s := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx := context.Background()
	if _, err := s.Apply(ctx, configaudit.AppliedVersion{Actor: "a", Digest: "d", Snapshot: map[string]any{"a": 1}}); err == nil {
		t.Errorf("Apply on a closed store must error")
	}
	if _, err := s.Applied(ctx); err == nil {
		t.Errorf("Applied on a closed store must error")
	}
	if _, err := s.Rollback(ctx, "a", "r"); err == nil {
		t.Errorf("Rollback on a closed store must error")
	}
}
