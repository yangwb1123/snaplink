package sessionhub

import (
	"context"
	"testing"
)

func TestMemoryLinkStore_LinkAndList(t *testing.T) {
	t.Parallel()
	store := NewMemoryLinkStore(0)
	ctx := context.Background()

	if err := store.Link(ctx, LinkRecord{GlobalSID: "g1", Protocol: ProtocolCore, ExternalRef: "sess-1", Subject: "user-1"}); err != nil {
		t.Fatalf("Link core: %v", err)
	}
	if err := store.Link(ctx, LinkRecord{GlobalSID: "g1", Protocol: ProtocolSAML, ExternalRef: "sess-1", Subject: "user-1"}); err != nil {
		t.Fatalf("Link saml: %v", err)
	}

	got, err := store.List(ctx, "g1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List len = %d, want 2: %+v", len(got), got)
	}
	if got[0].Protocol != ProtocolCore || got[1].Protocol != ProtocolSAML {
		t.Fatalf("unexpected order: %+v", got)
	}
}

func TestMemoryLinkStore_ListUnknownIsEmptyNotError(t *testing.T) {
	t.Parallel()
	store := NewMemoryLinkStore(0)
	got, err := store.List(context.Background(), "nope")
	if err != nil || got != nil {
		t.Fatalf("List unknown = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestMemoryLinkStore_LinkEmptyGlobalSID(t *testing.T) {
	t.Parallel()
	store := NewMemoryLinkStore(0)
	if err := store.Link(context.Background(), LinkRecord{Protocol: ProtocolCore}); err != ErrEmptyGlobalSID {
		t.Fatalf("Link empty gsid err = %v, want ErrEmptyGlobalSID", err)
	}
}

func TestMemoryLinkStore_DeleteAll(t *testing.T) {
	t.Parallel()
	store := NewMemoryLinkStore(0)
	ctx := context.Background()
	_ = store.Link(ctx, LinkRecord{GlobalSID: "g1", Protocol: ProtocolCore, ExternalRef: "sess-1"})

	if err := store.DeleteAll(ctx, "g1"); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	got, _ := store.List(ctx, "g1")
	if len(got) != 0 {
		t.Fatalf("List after DeleteAll = %+v, want empty", got)
	}
	// Idempotent: deleting again (or an unknown gsid) is a no-op, not an error.
	if err := store.DeleteAll(ctx, "g1"); err != nil {
		t.Fatalf("DeleteAll (again): %v", err)
	}
}

func TestMemoryLinkStore_EvictsOldestPastCapacity(t *testing.T) {
	t.Parallel()
	store := NewMemoryLinkStore(2)
	ctx := context.Background()
	_ = store.Link(ctx, LinkRecord{GlobalSID: "g1", Protocol: ProtocolCore, ExternalRef: "s1"})
	_ = store.Link(ctx, LinkRecord{GlobalSID: "g2", Protocol: ProtocolCore, ExternalRef: "s2"})
	_ = store.Link(ctx, LinkRecord{GlobalSID: "g3", Protocol: ProtocolCore, ExternalRef: "s3"})

	if got := store.sidCount(); got != 2 {
		t.Fatalf("sidCount = %d, want 2", got)
	}
	if got, _ := store.List(ctx, "g1"); len(got) != 0 {
		t.Fatalf("g1 should have been evicted, got %+v", got)
	}
	if got, _ := store.List(ctx, "g3"); len(got) != 1 {
		t.Fatalf("g3 should still be present, got %+v", got)
	}
}

func TestMemoryLinkStore_ListBySubject(t *testing.T) {
	t.Parallel()
	store := NewMemoryLinkStore(0)
	ctx := context.Background()

	// user-1 fanned into two global_sids (e.g. two separate logins); user-2
	// into one. ListBySubject must return every leg across ALL of user-1's
	// global_sids, and must not leak user-2's rows.
	_ = store.Link(ctx, LinkRecord{GlobalSID: "g1", Protocol: ProtocolCore, ExternalRef: "sess-1", Subject: "user-1"})
	_ = store.Link(ctx, LinkRecord{GlobalSID: "g1", Protocol: ProtocolSAML, ExternalRef: "sess-1", Subject: "user-1"})
	_ = store.Link(ctx, LinkRecord{GlobalSID: "g2", Protocol: ProtocolCore, ExternalRef: "sess-2", Subject: "user-1"})
	_ = store.Link(ctx, LinkRecord{GlobalSID: "g3", Protocol: ProtocolCore, ExternalRef: "sess-3", Subject: "user-2"})

	got, err := store.ListBySubject(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListBySubject(user-1) len = %d, want 3: %+v", len(got), got)
	}
	for _, rec := range got {
		if rec.Subject != "user-1" {
			t.Fatalf("ListBySubject(user-1) leaked a foreign row: %+v", rec)
		}
	}

	got2, err := store.ListBySubject(ctx, "user-2")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(got2) != 1 || got2[0].GlobalSID != "g3" {
		t.Fatalf("ListBySubject(user-2) = %+v, want exactly the g3 row", got2)
	}
}

func TestMemoryLinkStore_ListBySubjectUnknownIsEmptyNotError(t *testing.T) {
	t.Parallel()
	store := NewMemoryLinkStore(0)
	got, err := store.ListBySubject(context.Background(), "nobody")
	if err != nil || got != nil {
		t.Fatalf("ListBySubject unknown = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestNewGlobalSID_Unique(t *testing.T) {
	t.Parallel()
	a := NewGlobalSID()
	b := NewGlobalSID()
	if a == "" || b == "" {
		t.Fatal("NewGlobalSID returned empty value")
	}
	if a == b {
		t.Fatal("NewGlobalSID returned duplicate values")
	}
}
