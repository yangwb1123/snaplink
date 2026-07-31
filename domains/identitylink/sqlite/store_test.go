package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/domains/identitylink"
)

func TestStorePersistsAndEnforcesUniqueOwner(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "identity-links.db") + "?_pragma=busy_timeout(5000)"
	store, err := New(dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, err := store.Link(ctx, "user-1", "google", "subject-1")
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	again, err := store.Link(ctx, "user-1", "google", "subject-1")
	if err != nil || again.ID != first.ID {
		t.Fatalf("idempotent Link = %+v, %v; want id %q", again, err, first.ID)
	}
	if _, err := store.Link(ctx, "user-2", "google", "subject-1"); !errors.Is(err, identitylink.ErrAccountConflict) {
		t.Fatalf("second owner Link = %v, want ErrAccountConflict", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	store, err = New(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	links, err := store.ListByUser(ctx, "user-1")
	if err != nil || len(links) != 1 || links[0].ID != first.ID {
		t.Fatalf("persisted links = %+v, %v", links, err)
	}
}

func TestStoreAtomicMergeRevalidatesConflict(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "merge.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.Link(ctx, "winner", "google", "shared"); err != nil {
		t.Fatalf("winner Link: %v", err)
	}
	if _, err := store.Link(ctx, "loser", "github", "other"); err != nil {
		t.Fatalf("loser Link: %v", err)
	}
	conflict := identitylink.Conflict{
		Provider: "google", Subject: "shared",
		ExistingUserID: "winner", IncomingUserID: "loser",
	}
	if err := store.MergeUserLinks(ctx, conflict); err != nil {
		t.Fatalf("MergeUserLinks: %v", err)
	}
	winner, err := store.ListByUser(ctx, "winner")
	if err != nil || len(winner) != 2 {
		t.Fatalf("winner links = %+v, %v; want 2", winner, err)
	}
	if err := store.MergeUserLinks(ctx, identitylink.Conflict{
		Provider: "google", Subject: "shared",
		ExistingUserID: "stale-owner", IncomingUserID: "winner",
	}); !errors.Is(err, identitylink.ErrAccountConflict) {
		t.Fatalf("stale merge = %v, want ErrAccountConflict", err)
	}
	winner, _ = store.ListByUser(ctx, "winner")
	if len(winner) != 2 {
		t.Fatalf("stale merge mutated winner: %+v", winner)
	}
}
