package defaultimpl_test

import (
	"context"
	"sort"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
)

func TestMemorySubjectClientIndex_RecordListForget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	idx := defaultimpl.NewMemorySubjectClientIndex()

	if err := idx.RecordAccess(ctx, "alice", "app-a"); err != nil {
		t.Fatalf("RecordAccess: %v", err)
	}
	_ = idx.RecordAccess(ctx, "alice", "app-b")
	// Duplicate record is idempotent (set semantics).
	_ = idx.RecordAccess(ctx, "alice", "app-a")
	_ = idx.RecordAccess(ctx, "bob", "app-c")

	clients, err := idx.ListClients(ctx, "alice")
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	sort.Strings(clients)
	if len(clients) != 2 || clients[0] != "app-a" || clients[1] != "app-b" {
		t.Errorf("alice clients = %v, want [app-a app-b]", clients)
	}

	// Forget one client; the other survives.
	if err := idx.Forget(ctx, "alice", "app-a"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	after, _ := idx.ListClients(ctx, "alice")
	if len(after) != 1 || after[0] != "app-b" {
		t.Errorf("after forget = %v, want [app-b]", after)
	}

	// Forgetting the last client drops the subject entirely.
	if err := idx.Forget(ctx, "alice", "app-b"); err != nil {
		t.Fatalf("Forget(last): %v", err)
	}
	gone, _ := idx.ListClients(ctx, "alice")
	if len(gone) != 0 {
		t.Errorf("alice should be empty, got %v", gone)
	}

	// bob unaffected.
	bob, _ := idx.ListClients(ctx, "bob")
	if len(bob) != 1 {
		t.Errorf("bob clients = %v", bob)
	}
}

func TestMemorySubjectClientIndex_EmptyArgsAreNoOps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	idx := defaultimpl.NewMemorySubjectClientIndex()

	if err := idx.RecordAccess(ctx, "", "c"); err != nil {
		t.Errorf("RecordAccess(empty subject) = %v", err)
	}
	if err := idx.RecordAccess(ctx, "s", ""); err != nil {
		t.Errorf("RecordAccess(empty client) = %v", err)
	}
	if got, _ := idx.ListClients(ctx, ""); got != nil {
		t.Errorf("ListClients(empty) = %v, want nil", got)
	}
	if got, _ := idx.ListClients(ctx, "unknown"); got != nil {
		t.Errorf("ListClients(unknown) = %v, want nil", got)
	}
	if err := idx.Forget(ctx, "", "c"); err != nil {
		t.Errorf("Forget(empty subject) = %v", err)
	}
	if err := idx.Forget(ctx, "unknown", "c"); err != nil {
		t.Errorf("Forget(unknown subject) = %v", err)
	}
}
