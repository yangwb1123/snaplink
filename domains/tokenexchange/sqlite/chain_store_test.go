package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenexchange"
	tesqlite "github.com/yangwb1123/snaplink/domains/tokenexchange/sqlite"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

func newStore(t *testing.T) *tesqlite.ChainStore {
	t.Helper()
	s, err := tesqlite.New("file:" + t.TempDir() + "/tokenexchange_chains.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestChainStore_GetChain_MultiHop proves a 3-hop delegation chain persists
// across real sqlite rows and GetChain reassembles it oldest-first.
func TestChainStore_GetChain_MultiHop(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	now := time.Now()

	hops := []tokenexchange.ChainHop{
		{JTI: "jti-root", SubjectID: "alice", ClientID: "svc-a", RecordedAt: now},
		{JTI: "jti-mid", ParentJTI: "jti-root", SubjectID: "alice", ActorSubject: "svc-b", ClientID: "svc-b", ChainDepth: 1, RecordedAt: now.Add(time.Minute)},
		{JTI: "jti-leaf", ParentJTI: "jti-mid", SubjectID: "alice", ActorSubject: "svc-c", ClientID: "svc-c", ChainDepth: 2, RecordedAt: now.Add(2 * time.Minute)},
	}
	for _, h := range hops {
		if err := store.RecordHop(ctx, h); err != nil {
			t.Fatalf("RecordHop(%s): %v", h.JTI, err)
		}
	}

	chain, err := store.GetChain(ctx, "jti-leaf")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("GetChain length = %d, want 3", len(chain))
	}
	wantOrder := []string{"jti-root", "jti-mid", "jti-leaf"}
	for i, jti := range wantOrder {
		if chain[i].JTI != jti {
			t.Errorf("chain[%d].JTI = %q, want %q", i, chain[i].JTI, jti)
		}
	}
	if chain[2].ActorSubject != "svc-c" || chain[2].ChainDepth != 2 {
		t.Errorf("leaf hop fields not preserved: %+v", chain[2])
	}
	// recorded_at round-trips to at least second precision (stored as
	// UnixNano so this should be exact, but only second-precision is load
	// bearing for any consumer).
	if !chain[0].RecordedAt.Truncate(time.Second).Equal(now.Truncate(time.Second)) {
		t.Errorf("root RecordedAt = %v, want ~%v", chain[0].RecordedAt, now)
	}
}

func TestChainStore_GetChain_UnknownJTI(t *testing.T) {
	store := newStore(t)
	chain, err := store.GetChain(context.Background(), "never-recorded")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(chain) != 0 {
		t.Fatalf("GetChain for unknown jti = %d hops, want 0", len(chain))
	}
}

// TestChainStore_GetDescendants proves a fan-out is walked forward
// correctly, newest first, and respects a limit — using the SAME real
// sqlite-backed store as production.
func TestChainStore_GetDescendants(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	now := time.Now()

	hops := []tokenexchange.ChainHop{
		{JTI: "jti-root", SubjectID: "alice", RecordedAt: now},
		{JTI: "jti-child-a", ParentJTI: "jti-root", ActorSubject: "svc-a", RecordedAt: now.Add(time.Minute)},
		{JTI: "jti-child-b", ParentJTI: "jti-root", ActorSubject: "svc-b", RecordedAt: now.Add(2 * time.Minute)},
		{JTI: "jti-grandchild", ParentJTI: "jti-child-a", ActorSubject: "svc-c", RecordedAt: now.Add(3 * time.Minute)},
	}
	for _, h := range hops {
		if err := store.RecordHop(ctx, h); err != nil {
			t.Fatalf("RecordHop(%s): %v", h.JTI, err)
		}
	}

	descendants, err := store.GetDescendants(ctx, "jti-root", 0)
	if err != nil {
		t.Fatalf("GetDescendants: %v", err)
	}
	if len(descendants) != 3 {
		t.Fatalf("GetDescendants length = %d, want 3", len(descendants))
	}
	if descendants[0].JTI != "jti-grandchild" {
		t.Errorf("descendants[0].JTI = %q, want jti-grandchild (newest first)", descendants[0].JTI)
	}

	limited, err := store.GetDescendants(ctx, "jti-root", 2)
	if err != nil {
		t.Fatalf("GetDescendants (limited): %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("GetDescendants with limit=2 returned %d, want 2", len(limited))
	}
}

// TestChainStore_RecordHop_MissingJTI proves the primary-key guard rejects
// an unkeyed hop rather than silently writing an unreachable row.
func TestChainStore_RecordHop_MissingJTI(t *testing.T) {
	store := newStore(t)
	if err := store.RecordHop(context.Background(), tokenexchange.ChainHop{SubjectID: "alice"}); err == nil {
		t.Fatal("RecordHop with empty JTI: want error, got nil")
	}
}

// TestChainStore_PersistsAcrossReopen proves the whole point of this backend
// over the memory store: a recorded chain survives a process restart because
// it lives in the sqlite file, not a process-local map.
func TestChainStore_PersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + t.TempDir() + "/reopen.db"

	s1, err := tesqlite.New(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.RecordHop(ctx, tokenexchange.ChainHop{JTI: "survives-restart", SubjectID: "alice"}); err != nil {
		t.Fatalf("RecordHop: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := tesqlite.New(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	chain, err := s2.GetChain(ctx, "survives-restart")
	if err != nil {
		t.Fatalf("GetChain after reopen: %v", err)
	}
	if len(chain) != 1 || chain[0].SubjectID != "alice" {
		t.Errorf("hop did not survive reopen intact: %+v", chain)
	}
}

// TestChainStore_Ping proves the readiness-probe wiring point works against
// a real handle and reports closed after Close.
func TestChainStore_Ping(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := store.Ping(ctx); err == nil {
		t.Error("expected Ping to fail after Close")
	}
}

// TestChainStoreMaxVersion_MatchesLiveSchema proves the exported MaxVersion
// function used by cmd's boot-time schema guard reflects the same version a
// fresh store actually migrates to.
func TestChainStoreMaxVersion_MatchesLiveSchema(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	max := tesqlite.ChainStoreMaxVersion()

	if err := migrate.CheckSchema(ctx, store.DB(), "tokenexchange_chain_hops", max); err != nil {
		t.Errorf("CheckSchema at binary's own max version: %v", err)
	}
	if err := migrate.CheckSchema(ctx, store.DB(), "tokenexchange_chain_hops", max-1); !errors.Is(err, migrate.ErrSchemaTooNew) {
		t.Errorf("expected ErrSchemaTooNew for an older binary, got %v", err)
	}
}
