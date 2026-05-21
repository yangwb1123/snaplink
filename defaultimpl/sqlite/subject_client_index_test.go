package sqlite

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func newSubjectClientIndexForTest(t *testing.T) *SubjectClientIndex {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "sci.db") + "?_journal=WAL&_busy_timeout=5000"
	idx, err := NewSubjectClientIndex(dsn)
	if err != nil {
		t.Fatalf("NewSubjectClientIndex: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	return idx
}

func TestSubjectClientIndex_RecordAndList(t *testing.T) {
	idx := newSubjectClientIndexForTest(t)
	ctx := context.Background()

	for _, cid := range []string{"web", "mobile", "tv"} {
		if err := idx.RecordAccess(ctx, "alice", cid); err != nil {
			t.Fatalf("RecordAccess(%q): %v", cid, err)
		}
	}

	got, err := idx.ListClients(ctx, "alice")
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListClients alice: got %d clients %v want 3", len(got), got)
	}
	sort.Strings(got)
	want := []string{"mobile", "tv", "web"}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("ListClients alice[%d]: got %q want %q", i, got[i], w)
		}
	}
}

func TestSubjectClientIndex_ListUnknownReturnsNilNoError(t *testing.T) {
	idx := newSubjectClientIndexForTest(t)
	got, err := idx.ListClients(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("ListClients ghost: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for unknown subject, got %v", got)
	}
}

func TestSubjectClientIndex_RecordIsIdempotent(t *testing.T) {
	idx := newSubjectClientIndexForTest(t)
	ctx := context.Background()

	for range 5 {
		if err := idx.RecordAccess(ctx, "alice", "web"); err != nil {
			t.Fatalf("RecordAccess: %v", err)
		}
	}
	got, err := idx.ListClients(ctx, "alice")
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("idempotent record produced %d rows want 1: %v", len(got), got)
	}
}

func TestSubjectClientIndex_EmptySubjectOrClientIDNoOp(t *testing.T) {
	idx := newSubjectClientIndexForTest(t)
	ctx := context.Background()

	// Empty pair must not error and must not write a row.
	if err := idx.RecordAccess(ctx, "", "web"); err != nil {
		t.Fatalf("RecordAccess(empty subject): %v", err)
	}
	if err := idx.RecordAccess(ctx, "alice", ""); err != nil {
		t.Fatalf("RecordAccess(empty client_id): %v", err)
	}
	// And ListClients with empty subject must also be a clean no-op.
	got, err := idx.ListClients(ctx, "")
	if err != nil {
		t.Fatalf("ListClients(empty): %v", err)
	}
	if got != nil {
		t.Fatalf("ListClients(empty) returned %v, want nil", got)
	}
}

func TestSubjectClientIndex_Forget(t *testing.T) {
	idx := newSubjectClientIndexForTest(t)
	ctx := context.Background()

	for _, cid := range []string{"web", "mobile", "tv"} {
		_ = idx.RecordAccess(ctx, "alice", cid)
	}
	if err := idx.Forget(ctx, "alice", "mobile"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	got, err := idx.ListClients(ctx, "alice")
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("post-Forget count: got %d want 2", len(got))
	}
	for _, cid := range got {
		if cid == "mobile" {
			t.Fatal("Forget did not remove mobile")
		}
	}
}

func TestSubjectClientIndex_ForgetUnknownIsNoOp(t *testing.T) {
	idx := newSubjectClientIndexForTest(t)
	ctx := context.Background()
	if err := idx.Forget(ctx, "ghost", "web"); err != nil {
		t.Fatalf("Forget unknown: %v", err)
	}
	if err := idx.Forget(ctx, "alice", ""); err != nil {
		t.Fatalf("Forget empty client_id: %v", err)
	}
}

func TestSubjectClientIndex_SubjectsIsolated(t *testing.T) {
	idx := newSubjectClientIndexForTest(t)
	ctx := context.Background()

	_ = idx.RecordAccess(ctx, "alice", "web")
	_ = idx.RecordAccess(ctx, "bob", "mobile")

	a, _ := idx.ListClients(ctx, "alice")
	if len(a) != 1 || a[0] != "web" {
		t.Fatalf("alice: got %v", a)
	}
	b, _ := idx.ListClients(ctx, "bob")
	if len(b) != 1 || b[0] != "mobile" {
		t.Fatalf("bob: got %v", b)
	}
}

func TestSubjectClientIndex_OrderedByLastSeenDesc(t *testing.T) {
	idx := newSubjectClientIndexForTest(t)
	ctx := context.Background()

	// Stagger the inserts so last_seen ordering is observable.
	_ = idx.RecordAccess(ctx, "alice", "first")
	time.Sleep(2 * time.Millisecond)
	_ = idx.RecordAccess(ctx, "alice", "second")
	time.Sleep(2 * time.Millisecond)
	_ = idx.RecordAccess(ctx, "alice", "third")

	got, err := idx.ListClients(ctx, "alice")
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(got) != 3 || got[0] != "third" || got[1] != "second" || got[2] != "first" {
		t.Fatalf("expected DESC by last_seen [third, second, first], got %v", got)
	}
}

func TestSubjectClientIndex_CrossInstanceSharing(t *testing.T) {
	// Multi-replica BCL fan-out is the whole point: a token issued
	// on replica A must show up in the ListClients result on replica B
	// so its logout reaches every client.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_busy_timeout=5000"

	idxA, err := NewSubjectClientIndex(dsn)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	defer idxA.Close()
	idxB, err := NewSubjectClientIndex(dsn)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	defer idxB.Close()

	if err := idxA.RecordAccess(context.Background(), "alice", "web"); err != nil {
		t.Fatalf("A.RecordAccess: %v", err)
	}
	got, err := idxB.ListClients(context.Background(), "alice")
	if err != nil {
		t.Fatalf("B.ListClients: %v", err)
	}
	if len(got) != 1 || got[0] != "web" {
		t.Fatalf("cross-instance: got %v want [web]", got)
	}
}
