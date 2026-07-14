package memory

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/tokenexchange"
)

func TestChainStore_RecordHop_MissingJTI(t *testing.T) {
	s := NewChainStore()
	if err := s.RecordHop(context.Background(), tokenexchange.ChainHop{SubjectID: "alice"}); err != ErrMissingJTI {
		t.Fatalf("RecordHop with empty JTI: got %v, want ErrMissingJTI", err)
	}
}

// TestChainStore_GetChain_MultiHop proves a 3-hop delegation chain
// (root -> mid -> leaf) round-trips through RecordHop and that GetChain
// returns it ordered oldest (root) first.
func TestChainStore_GetChain_MultiHop(t *testing.T) {
	ctx := context.Background()
	s := NewChainStore()
	now := time.Now()

	root := tokenexchange.ChainHop{JTI: "jti-root", SubjectID: "alice", ClientID: "svc-a", RecordedAt: now}
	mid := tokenexchange.ChainHop{JTI: "jti-mid", ParentJTI: "jti-root", SubjectID: "alice", ActorSubject: "svc-b", ClientID: "svc-b", ChainDepth: 1, RecordedAt: now.Add(time.Minute)}
	leaf := tokenexchange.ChainHop{JTI: "jti-leaf", ParentJTI: "jti-mid", SubjectID: "alice", ActorSubject: "svc-c", ClientID: "svc-c", ChainDepth: 2, RecordedAt: now.Add(2 * time.Minute)}

	for _, h := range []tokenexchange.ChainHop{root, mid, leaf} {
		if err := s.RecordHop(ctx, h); err != nil {
			t.Fatalf("RecordHop(%s): %v", h.JTI, err)
		}
	}

	chain, err := s.GetChain(ctx, "jti-leaf")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("GetChain length = %d, want 3", len(chain))
	}
	wantOrder := []string{"jti-root", "jti-mid", "jti-leaf"}
	for i, jti := range wantOrder {
		if chain[i].JTI != jti {
			t.Errorf("chain[%d].JTI = %q, want %q (want oldest-first order)", i, chain[i].JTI, jti)
		}
	}
	if chain[2].ActorSubject != "svc-c" || chain[2].ChainDepth != 2 {
		t.Errorf("leaf hop fields not preserved: %+v", chain[2])
	}
}

// TestChainStore_GetChain_UnknownJTI proves an unrecorded jti returns an
// empty (nil) chain, not an error.
func TestChainStore_GetChain_UnknownJTI(t *testing.T) {
	s := NewChainStore()
	chain, err := s.GetChain(context.Background(), "never-recorded")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(chain) != 0 {
		t.Fatalf("GetChain for unknown jti = %d hops, want 0", len(chain))
	}
}

// TestChainStore_GetDescendants proves a fan-out (one root re-exchanged into
// two independent downstream hops) is walked forward correctly, newest first,
// and respects a limit.
func TestChainStore_GetDescendants(t *testing.T) {
	ctx := context.Background()
	s := NewChainStore()
	now := time.Now()

	root := tokenexchange.ChainHop{JTI: "jti-root", SubjectID: "alice", RecordedAt: now}
	childA := tokenexchange.ChainHop{JTI: "jti-child-a", ParentJTI: "jti-root", ActorSubject: "svc-a", RecordedAt: now.Add(time.Minute)}
	childB := tokenexchange.ChainHop{JTI: "jti-child-b", ParentJTI: "jti-root", ActorSubject: "svc-b", RecordedAt: now.Add(2 * time.Minute)}
	grandchild := tokenexchange.ChainHop{JTI: "jti-grandchild", ParentJTI: "jti-child-a", ActorSubject: "svc-c", RecordedAt: now.Add(3 * time.Minute)}

	for _, h := range []tokenexchange.ChainHop{root, childA, childB, grandchild} {
		if err := s.RecordHop(ctx, h); err != nil {
			t.Fatalf("RecordHop(%s): %v", h.JTI, err)
		}
	}

	descendants, err := s.GetDescendants(ctx, "jti-root", 0)
	if err != nil {
		t.Fatalf("GetDescendants: %v", err)
	}
	if len(descendants) != 3 {
		t.Fatalf("GetDescendants length = %d, want 3 (childA, childB, grandchild)", len(descendants))
	}
	// Newest-recorded first.
	if descendants[0].JTI != "jti-grandchild" {
		t.Errorf("descendants[0].JTI = %q, want jti-grandchild (newest first)", descendants[0].JTI)
	}

	limited, err := s.GetDescendants(ctx, "jti-root", 2)
	if err != nil {
		t.Fatalf("GetDescendants (limited): %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("GetDescendants with limit=2 returned %d, want 2", len(limited))
	}
}

// TestChainStore_GetDescendants_Leaf proves a hop with no children returns
// an empty descendant list, not an error.
func TestChainStore_GetDescendants_Leaf(t *testing.T) {
	ctx := context.Background()
	s := NewChainStore()
	if err := s.RecordHop(ctx, tokenexchange.ChainHop{JTI: "solo"}); err != nil {
		t.Fatalf("RecordHop: %v", err)
	}
	descendants, err := s.GetDescendants(ctx, "solo", 0)
	if err != nil {
		t.Fatalf("GetDescendants: %v", err)
	}
	if len(descendants) != 0 {
		t.Fatalf("GetDescendants for a leaf = %d, want 0", len(descendants))
	}
}

var _ tokenexchange.ChainStore = (*ChainStore)(nil)
