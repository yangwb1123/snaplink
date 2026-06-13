package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/authenticators/webauthn"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

func newSessionStoreForTest(t *testing.T) *SessionStore {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "sessions.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	store, err := NewSessionStore(dsn)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestSessionStore_PutThenTake(t *testing.T) {
	store := newSessionStoreForTest(t)
	ctx := context.Background()
	want := &gw.SessionData{Challenge: "abc", UserID: []byte("alice")}

	if err := store.Put(ctx, "s1", want, time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Take(ctx, "s1")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got.Challenge != want.Challenge {
		t.Fatalf("challenge round-trip: got %q want %q", got.Challenge, want.Challenge)
	}
	if string(got.UserID) != string(want.UserID) {
		t.Fatalf("userID round-trip: got %q want %q", got.UserID, want.UserID)
	}
}

func TestSessionStore_TakeIsSingleUse(t *testing.T) {
	store := newSessionStoreForTest(t)
	ctx := context.Background()
	if err := store.Put(ctx, "s1", &gw.SessionData{Challenge: "x"}, time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, err := store.Take(ctx, "s1"); err != nil {
		t.Fatalf("first Take: %v", err)
	}
	_, err := store.Take(ctx, "s1")
	if !errors.Is(err, webauthn.ErrSessionUnknown) {
		t.Fatalf("second Take: got %v want ErrSessionUnknown (single-use)", err)
	}
}

func TestSessionStore_ExpiredSessionReturnsExpired(t *testing.T) {
	store := newSessionStoreForTest(t)
	ctx := context.Background()
	if err := store.Put(ctx, "s1", &gw.SessionData{Challenge: "x"}, -1*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}

	_, err := store.Take(ctx, "s1")
	if !errors.Is(err, webauthn.ErrSessionExpired) {
		t.Fatalf("got %v, want ErrSessionExpired", err)
	}
	// And the entry should be gone — second Take returns Unknown.
	_, err = store.Take(ctx, "s1")
	if !errors.Is(err, webauthn.ErrSessionUnknown) {
		t.Fatalf("post-expired Take: got %v want ErrSessionUnknown", err)
	}
}

func TestSessionStore_TakeUnknownReturnsSentinel(t *testing.T) {
	store := newSessionStoreForTest(t)
	_, err := store.Take(context.Background(), "ghost")
	if !errors.Is(err, webauthn.ErrSessionUnknown) {
		t.Fatalf("got %v, want ErrSessionUnknown", err)
	}
}

func TestSessionStore_PutUpsertsOnSameID(t *testing.T) {
	// Second Put with the same id overwrites — defense against a rare
	// collision on the helper's 24-byte random session id.
	store := newSessionStoreForTest(t)
	ctx := context.Background()
	if err := store.Put(ctx, "s1", &gw.SessionData{Challenge: "first"}, time.Minute); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	if err := store.Put(ctx, "s1", &gw.SessionData{Challenge: "second"}, time.Minute); err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	got, err := store.Take(ctx, "s1")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got.Challenge != "second" {
		t.Fatalf("challenge: got %q want second (Put upsert)", got.Challenge)
	}
}

func TestSessionStore_CrossInstanceSharing(t *testing.T) {
	// Ceremony Begin* on replica A, Finish* on replica B — both
	// store handles point at the same DB file.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"

	storeA, err := NewSessionStore(dsn)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	defer func() { _ = storeA.Close() }()
	storeB, err := NewSessionStore(dsn)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	defer func() { _ = storeB.Close() }()

	ctx := context.Background()
	if err := storeA.Put(ctx, "cross-id", &gw.SessionData{Challenge: "xyz"}, time.Minute); err != nil {
		t.Fatalf("A.Put: %v", err)
	}
	got, err := storeB.Take(ctx, "cross-id")
	if err != nil {
		t.Fatalf("B.Take: %v", err)
	}
	if got.Challenge != "xyz" {
		t.Fatalf("cross-instance: got %q want xyz", got.Challenge)
	}
	// And single-use crosses the wire too.
	_, err = storeA.Take(ctx, "cross-id")
	if !errors.Is(err, webauthn.ErrSessionUnknown) {
		t.Fatalf("A.Take after B.Take: got %v want ErrSessionUnknown", err)
	}
}
