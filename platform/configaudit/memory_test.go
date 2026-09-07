package configaudit

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestMemoryStore_RecordAndList(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()

	if err := s.Record(ctx, Entry{Actor: "alice", Resource: "client", ResourceID: "c1"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := s.Record(ctx, Entry{Actor: "bob", Resource: "tenant", ResourceID: "t1"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries, err := s.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// Newest first.
	if entries[0].Actor != "bob" || entries[1].Actor != "alice" {
		t.Errorf("expected newest-first order [bob, alice], got [%s, %s]", entries[0].Actor, entries[1].Actor)
	}
	for _, e := range entries {
		if e.ID == "" {
			t.Errorf("Record must assign an ID when the caller left it empty")
		}
		if e.RecordedAt.IsZero() {
			t.Errorf("Record must assign RecordedAt when the caller left it zero")
		}
	}
}

func TestMemoryStore_FilterByResource(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	_ = s.Record(ctx, Entry{Resource: "client", ResourceID: "c1"})
	_ = s.Record(ctx, Entry{Resource: "tenant", ResourceID: "t1"})
	_ = s.Record(ctx, Entry{Resource: "client", ResourceID: "c2"})

	entries, err := s.List(ctx, Filter{Resource: "client"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 client entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Resource != "client" {
			t.Errorf("filter leaked a non-matching resource: %+v", e)
		}
	}
}

func TestMemoryStore_FilterBySince(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	old := time.Now().Add(-2 * time.Hour)
	_ = s.Record(ctx, Entry{Resource: "client", ResourceID: "old", RecordedAt: old})
	_ = s.Record(ctx, Entry{Resource: "client", ResourceID: "new", RecordedAt: time.Now()})

	entries, err := s.List(ctx, Filter{Since: time.Now().Add(-1 * time.Hour)})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].ResourceID != "new" {
		t.Fatalf("expected only the entry recorded after Since, got %+v", entries)
	}
}

func TestMemoryStore_LimitAndCapacityEviction(t *testing.T) {
	s := NewMemoryStore(3)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = s.Record(ctx, Entry{Resource: "client", ResourceID: string(rune('a' + i))})
	}
	if got := s.Len(); got != 3 {
		t.Fatalf("expected capacity-bounded Len() == 3, got %d", got)
	}
	entries, err := s.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after eviction, got %d", len(entries))
	}
	// The oldest two (a, b) must have been evicted; c/d/e survive.
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.ResourceID] = true
	}
	for _, want := range []string{"c", "d", "e"} {
		if !seen[want] {
			t.Errorf("expected surviving entry %q, got %+v", want, entries)
		}
	}

	limited, err := s.List(ctx, Filter{Limit: 1})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("expected Limit: 1 to return exactly 1 entry, got %d", len(limited))
	}
}

func TestMemoryStore_SatisfiesStoreInterface(t *testing.T) {
	var _ Store = NewMemoryStore(0)
}

func TestMemoryStore_Applied_EmptyReturnsErr(t *testing.T) {
	s := NewMemoryStore(0)
	if _, err := s.Applied(context.Background()); err != ErrNoAppliedVersion {
		t.Fatalf("Applied on an empty store = %v, want ErrNoAppliedVersion", err)
	}
}

func TestMemoryStore_Apply_AppendsHistoryAndChainsVersions(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	v1, err := s.Apply(ctx, AppliedVersion{Actor: "a", Digest: "d1", Reason: "r1", Snapshot: map[string]any{"name": "sso-1"}})
	if err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if v1.ID == "" || v1.AppliedAt.IsZero() || v1.PrevID != "" {
		t.Errorf("first version must be ID/AppliedAt-assigned with no prev: %+v", v1)
	}
	v2, err := s.Apply(ctx, AppliedVersion{Actor: "b", Digest: "d2", Reason: "r2", Snapshot: map[string]any{"name": "sso-2"}})
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
	if got.ID != v2.ID || got.Snapshot["name"] != "sso-2" {
		t.Errorf("Applied must return the latest version, got %+v", got)
	}
	// The apply appends a config_history entry with the redacted diff.
	entries, err := s.List(ctx, Filter{Resource: "config"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 config entries, got %d", len(entries))
	}
	if entries[0].ResourceID != v2.ID || entries[0].Actor != "b" {
		t.Errorf("newest entry must describe v2, got %+v", entries[0])
	}
	// Diff of redacted baselines: name changed sso-1 -> sso-2.
	found := false
	for _, op := range entries[0].Patch {
		if op.Path == "/name" && op.Value == "sso-2" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a /name replace op in the apply entry, got %+v", entries[0].Patch)
	}
}

func TestMemoryStore_Apply_RedactsSecretsInHistory(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	if _, err := s.Apply(ctx, AppliedVersion{Actor: "a", Digest: "d1", Snapshot: map[string]any{"db_dsn": "postgres://user:pass@h"}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := s.Apply(ctx, AppliedVersion{Actor: "b", Digest: "d2", Snapshot: map[string]any{"db_dsn": "postgres://user:pass2@h"}}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	entries, err := s.List(ctx, Filter{Resource: "config"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		for _, op := range e.Patch {
			if op.Path == "/db_dsn" && op.Value != "***" {
				t.Errorf("history patch must never carry a plaintext secret: %+v", e.Patch)
			}
		}
	}
}

func TestMemoryStore_Rollback_RestoresPreviousAndStaysAppendOnly(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	_, _ = s.Apply(ctx, AppliedVersion{Actor: "a", Digest: "d1", Snapshot: map[string]any{"rate_limit": float64(10)}})
	v2, _ := s.Apply(ctx, AppliedVersion{Actor: "b", Digest: "d2", Snapshot: map[string]any{"rate_limit": float64(40)}})

	v3, err := s.Rollback(ctx, "c", "revert")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if v3.PrevID != v2.ID {
		t.Errorf("rollback version must link the rolled-back-from version, got %q want %q", v3.PrevID, v2.ID)
	}
	if v3.Snapshot["rate_limit"] != float64(10) {
		t.Errorf("rollback must restore the first snapshot, got %+v", v3.Snapshot)
	}
	got, err := s.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if got.ID != v3.ID {
		t.Errorf("Applied after rollback = %s, want the rollback version %s", got.ID, v3.ID)
	}
	if n := len(s.appliedVersions()); n != 3 {
		t.Errorf("version chain must stay append-only (3 versions), got %d", n)
	}
	entries, err := s.List(ctx, Filter{Resource: "config"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 config entries (2 applies + 1 rollback), got %d", len(entries))
	}
	if entries[0].Actor != "c" {
		t.Errorf("newest entry must be the rollback by c, got %+v", entries[0])
	}
}

func TestMemoryStore_Rollback_NoPreviousReturnsErr(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	if _, err := s.Rollback(ctx, "a", "r"); err != ErrNoAppliedVersion {
		t.Errorf("Rollback on empty store = %v, want ErrNoAppliedVersion", err)
	}
	_, _ = s.Apply(ctx, AppliedVersion{Actor: "a", Digest: "d1", Snapshot: map[string]any{"a": 1}})
	if _, err := s.Rollback(ctx, "a", "r"); err != ErrNoAppliedVersion {
		t.Errorf("Rollback with a single version = %v, want ErrNoAppliedVersion", err)
	}
}

func TestMemoryStore_ClonesNestedSnapshotsOnApply(t *testing.T) {
	s := NewMemoryStore(0)
	input := nestedMemorySnapshot()
	applied := mustApplySnapshot(t, s, input)

	mutateNestedMemorySnapshot(input, "input mutation")
	mutateNestedMemorySnapshot(applied.Snapshot, "return mutation")

	got, err := s.Applied(context.Background())
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	assertMemorySnapshot(t, got.Snapshot, nestedMemorySnapshot())
	versions := s.appliedVersions()
	if len(versions) != 1 {
		t.Fatalf("expected one applied version, got %d", len(versions))
	}
	assertMemorySnapshot(t, versions[0].Snapshot, nestedMemorySnapshot())

	entries, err := s.List(context.Background(), Filter{Resource: "config"})
	if err != nil || len(entries) != 1 {
		t.Fatalf("List config history: entries=%d err=%v", len(entries), err)
	}
	patchValue, ok := entries[0].Patch[0].Value.(map[string]any)
	if !ok {
		t.Fatalf("expected nested map patch value, got %T", entries[0].Patch[0].Value)
	}
	assertMemorySnapshot(t, patchValue, nestedMemorySnapshot()["nested"].(map[string]any))
}

func TestMemoryStore_ClonesAppliedAndRollbackReturns(t *testing.T) {
	s := NewMemoryStore(0)
	first := nestedMemorySnapshot()
	mustApplySnapshot(t, s, first)
	second := nestedMemorySnapshot()
	mutateNestedMemorySnapshot(second, "second")
	mustApplySnapshot(t, s, second)

	rolled, err := s.Rollback(context.Background(), "rollback", "test")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	mutateNestedMemorySnapshot(rolled.Snapshot, "rollback return")
	got, err := s.Applied(context.Background())
	if err != nil {
		t.Fatalf("Applied after rollback: %v", err)
	}
	assertMemorySnapshot(t, got.Snapshot, first)

	mutateNestedMemorySnapshot(got.Snapshot, "applied return")
	again, err := s.Applied(context.Background())
	if err != nil {
		t.Fatalf("Applied after returned mutation: %v", err)
	}
	assertMemorySnapshot(t, again.Snapshot, first)
}

func TestMemoryStore_ClonesCanaryReturns(t *testing.T) {
	s := NewMemoryStore(0)
	baseline := nestedMemorySnapshot()
	mustApplySnapshot(t, s, baseline)
	candidate := nestedMemorySnapshot()
	mutateNestedMemorySnapshot(candidate, "candidate")
	wantCandidate := nestedMemorySnapshot()
	mutateNestedMemorySnapshot(wantCandidate, "candidate")

	got, state, err := s.BeginCanary(context.Background(), AppliedVersion{Snapshot: candidate}, CanaryState{})
	if err != nil {
		t.Fatalf("BeginCanary: %v", err)
	}
	mutateNestedMemorySnapshot(candidate, "input mutation")
	mutateNestedMemorySnapshot(got.Snapshot, "return mutation")
	stored, err := s.Applied(context.Background())
	if err != nil {
		t.Fatalf("Applied during canary: %v", err)
	}
	assertMemorySnapshot(t, stored.Snapshot, wantCandidate)

	reported, err := s.Canary(context.Background())
	if err != nil {
		t.Fatalf("Canary: %v", err)
	}
	reported.Detail = "caller mutation"
	unchanged, _ := s.Canary(context.Background())
	if unchanged.Detail == "caller mutation" {
		t.Fatal("Canary returned state alias")
	}

	restored, _, err := s.RollbackCanary(context.Background(), state.ID, "system", "test rollback")
	if err != nil {
		t.Fatalf("RollbackCanary: %v", err)
	}
	mutateNestedMemorySnapshot(restored.Snapshot, "rollback return")
	latest, err := s.Applied(context.Background())
	if err != nil {
		t.Fatalf("Applied after canary rollback: %v", err)
	}
	assertMemorySnapshot(t, latest.Snapshot, baseline)
}

func TestMemoryStore_ClonesNestedRecordPatchValues(t *testing.T) {
	s := NewMemoryStore(0)
	value := nestedMemorySnapshot()
	entry := Entry{Patch: []Op{{Op: "add", Path: "/nested", Value: value}}}
	if err := s.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record: %v", err)
	}
	mutateNestedMemorySnapshot(value, "input mutation")
	entry.Patch[0].Value = map[string]any{"replaced": true}

	entries, err := s.List(context.Background(), Filter{})
	if err != nil || len(entries) != 1 {
		t.Fatalf("List: entries=%d err=%v", len(entries), err)
	}
	gotValue, ok := entries[0].Patch[0].Value.(map[string]any)
	if !ok {
		t.Fatalf("expected nested map patch value, got %T", entries[0].Patch[0].Value)
	}
	assertMemorySnapshot(t, gotValue, nestedMemorySnapshot())
	mutateNestedMemorySnapshot(gotValue, "return mutation")

	again, err := s.List(context.Background(), Filter{})
	if err != nil || len(again) != 1 {
		t.Fatalf("List after returned mutation: entries=%d err=%v", len(again), err)
	}
	storedValue := again[0].Patch[0].Value.(map[string]any)
	assertMemorySnapshot(t, storedValue, nestedMemorySnapshot())
}

func mustApplySnapshot(t *testing.T, s *MemoryStore, snapshot map[string]any) AppliedVersion {
	t.Helper()
	version, err := s.Apply(context.Background(), AppliedVersion{Actor: "test", Snapshot: snapshot})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return version
}

func nestedMemorySnapshot() map[string]any {
	return map[string]any{
		"nested": map[string]any{
			"object": map[string]any{"name": "stable"},
			"items":  []any{map[string]any{"value": "stable"}},
			"uris":   []string{"https://stable.example"},
			"labels": map[string]string{"environment": "stable"},
		},
	}
}

func mutateNestedMemorySnapshot(snapshot map[string]any, value string) {
	nested := snapshot["nested"].(map[string]any)
	nested["object"].(map[string]any)["name"] = value
	nested["items"].([]any)[0].(map[string]any)["value"] = value
	nested["uris"].([]string)[0] = value
	nested["labels"].(map[string]string)["environment"] = value
}

func assertMemorySnapshot(t *testing.T, got, want map[string]any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("snapshot changed: got %#v, want %#v", got, want)
	}
}
