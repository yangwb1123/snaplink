package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso"
)

func newSessionManagerForTest(t *testing.T) *SessionManager {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "sessions.db") + "?_journal=WAL&_busy_timeout=5000"
	mgr, err := NewSessionManager(dsn, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

func TestSessionManager_CreateAndGet(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	created, err := mgr.Create(ctx, "alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" || created.UserID != "alice" {
		t.Fatalf("bad created session: %#v", created)
	}
	if created.CreatedAt.IsZero() || created.ExpiresAt.IsZero() {
		t.Fatal("timestamps not populated on create")
	}
	if !created.ExpiresAt.After(created.CreatedAt) {
		t.Fatalf("ExpiresAt %v must be after CreatedAt %v", created.ExpiresAt, created.CreatedAt)
	}

	got, err := mgr.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID || got.UserID != created.UserID {
		t.Fatalf("get mismatch: got %#v want %#v", got, created)
	}
	if got.CreatedAt.UnixNano() != created.CreatedAt.UnixNano() {
		t.Fatalf("CreatedAt: got %v want %v", got.CreatedAt, created.CreatedAt)
	}
	if got.ExpiresAt.UnixNano() != created.ExpiresAt.UnixNano() {
		t.Fatalf("ExpiresAt: got %v want %v", got.ExpiresAt, created.ExpiresAt)
	}
	if got.Revoked {
		t.Fatal("Revoked should default to false")
	}
}

func TestSessionManager_GetUnknownReturnsNotFound(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	_, err := mgr.Get(context.Background(), "nonexistent-id")
	if !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("got %v, want ErrSessionNotFound", err)
	}
}

func TestSessionManager_DestroyRemoves(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	created, _ := mgr.Create(ctx, "alice")
	if err := mgr.Destroy(ctx, created.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	_, err := mgr.Get(ctx, created.ID)
	if !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("post-Destroy Get: got %v, want ErrSessionNotFound", err)
	}
	// Destroy is idempotent — second call should not error.
	if err := mgr.Destroy(ctx, created.ID); err != nil {
		t.Fatalf("idempotent Destroy: %v", err)
	}
}

func TestSessionManager_RefreshExtendsExpiresAt(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	created, _ := mgr.Create(ctx, "alice")
	// Sleep so the new ExpiresAt is measurably different.
	time.Sleep(2 * time.Millisecond)

	refreshed, err := mgr.Refresh(ctx, created.ID)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !refreshed.ExpiresAt.After(created.ExpiresAt) {
		t.Fatalf("Refresh did not extend ExpiresAt: created=%v refreshed=%v",
			created.ExpiresAt, refreshed.ExpiresAt)
	}
	if refreshed.UserID != "alice" {
		t.Fatalf("UserID lost on refresh: %q", refreshed.UserID)
	}
}

func TestSessionManager_RefreshUnknownReturnsNotFound(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	_, err := mgr.Refresh(context.Background(), "nonexistent")
	if !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("got %v, want ErrSessionNotFound", err)
	}
}

func TestSessionManager_ListByUserFiltersByOwner(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	a1, _ := mgr.Create(ctx, "alice")
	a2, _ := mgr.Create(ctx, "alice")
	_, _ = mgr.Create(ctx, "bob")

	aliceSessions, err := mgr.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListByUser alice: %v", err)
	}
	if len(aliceSessions) != 2 {
		t.Fatalf("alice sessions: got %d want 2", len(aliceSessions))
	}
	seen := map[string]bool{a1.ID: false, a2.ID: false}
	for _, s := range aliceSessions {
		if _, ok := seen[s.ID]; ok {
			seen[s.ID] = true
		}
	}
	for id, ok := range seen {
		if !ok {
			t.Fatalf("missing session %q from ListByUser result", id)
		}
	}

	bobSessions, err := mgr.ListByUser(ctx, "bob")
	if err != nil {
		t.Fatalf("ListByUser bob: %v", err)
	}
	if len(bobSessions) != 1 {
		t.Fatalf("bob sessions: got %d want 1", len(bobSessions))
	}

	noOne, err := mgr.ListByUser(ctx, "ghost")
	if err != nil {
		t.Fatalf("ListByUser ghost: %v", err)
	}
	if len(noOne) != 0 {
		t.Fatalf("ghost sessions: got %d want 0", len(noOne))
	}
}

func TestSessionManager_ListAllReturnsEverything(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	_, _ = mgr.Create(ctx, "alice")
	_, _ = mgr.Create(ctx, "bob")
	_, _ = mgr.Create(ctx, "carol")

	all, err := mgr.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListAll: got %d want 3", len(all))
	}
}

func TestSessionManager_DefaultsToConfiguredTTL(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "default-ttl.db")
	mgr, err := NewSessionManager(dsn, 0) // zero = use sso.DefaultSessionDuration
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer mgr.Close()

	if mgr.ttl != sso.DefaultSessionDuration {
		t.Fatalf("ttl = %v, want sso.DefaultSessionDuration (%v)", mgr.ttl, sso.DefaultSessionDuration)
	}
	session, _ := mgr.Create(context.Background(), "alice")
	dur := session.ExpiresAt.Sub(session.CreatedAt)
	// Allow a few-ms scheduling slack — the two timestamps are
	// captured between two clock samples inside Create.
	if dur < sso.DefaultSessionDuration-time.Second || dur > sso.DefaultSessionDuration+time.Second {
		t.Fatalf("Create duration = %v, want ~%v", dur, sso.DefaultSessionDuration)
	}
}

func TestSessionManager_CrossInstanceSharing(t *testing.T) {
	// The whole point of SQLite-backed sessions is that a session
	// minted on one process is visible to another against the same
	// DB file — the multi-replica use case.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_busy_timeout=5000"

	mgrA, err := NewSessionManager(dsn, time.Hour)
	if err != nil {
		t.Fatalf("instance A: %v", err)
	}
	defer mgrA.Close()
	mgrB, err := NewSessionManager(dsn, time.Hour)
	if err != nil {
		t.Fatalf("instance B: %v", err)
	}
	defer mgrB.Close()

	created, err := mgrA.Create(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Create on A: %v", err)
	}
	got, err := mgrB.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get on B: %v", err)
	}
	if got.UserID != "alice" || got.ID != created.ID {
		t.Fatalf("cross-instance session mismatch: got %#v want %#v", got, created)
	}
}
