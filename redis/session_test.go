package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso"
)

func TestSessionCreateGetDestroy(t *testing.T) {
	_, rdb := newTestClient(t)
	sm := NewSessionManager(rdb, WithSessionTTL(time.Hour))
	ctx := context.Background()

	sess, err := sm.Create(ctx, "alice")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sess.UserID != "alice" || sess.ID == "" {
		t.Fatalf("bad session: %+v", sess)
	}

	got, err := sm.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != sess.ID || got.UserID != "alice" {
		t.Fatalf("get mismatch: %+v", got)
	}

	if err := sm.Destroy(ctx, sess.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := sm.Get(ctx, sess.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("get after destroy: want ErrSessionNotFound, got %v", err)
	}
}

func TestSessionGetUnknown(t *testing.T) {
	_, rdb := newTestClient(t)
	sm := NewSessionManager(rdb)
	if _, err := sm.Get(context.Background(), "nope"); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("get unknown: want ErrSessionNotFound, got %v", err)
	}
}

// TestSessionRefreshExtends locks the happy path: a live session extends.
func TestSessionRefreshExtends(t *testing.T) {
	_, rdb := newTestClient(t)
	sm := NewSessionManager(rdb, WithSessionTTL(time.Hour))
	ctx := context.Background()

	sess, err := sm.Create(ctx, "bob")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	orig := sess.ExpiresAt
	time.Sleep(2 * time.Millisecond)
	refreshed, err := sm.Refresh(ctx, sess.ID)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !refreshed.ExpiresAt.After(orig) {
		t.Fatalf("refresh did not extend: orig=%v new=%v", orig, refreshed.ExpiresAt)
	}
}

// TestSessionRefreshRefusesExpired is the §2 "captured expired session id
// can't be resurrected" invariant. An expired session must NOT be
// extended by Refresh — it must read as ErrSessionNotFound, never silently
// come back to life.
func TestSessionRefreshRefusesExpired(t *testing.T) {
	mr, rdb := newTestClient(t)
	// 1s TTL so we can drive expiry deterministically via miniredis' clock.
	sm := NewSessionManager(rdb, WithSessionTTL(time.Second))
	ctx := context.Background()

	sess, err := sm.Create(ctx, "carol")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Advance miniredis' clock past the expiry: both the explicit
	// expires_at field and the key TTL are now in the past.
	mr.FastForward(2 * time.Second)

	if _, err := sm.Refresh(ctx, sess.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("refresh of expired: want ErrSessionNotFound, got %v", err)
	}
	if _, err := sm.Get(ctx, sess.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("get of expired: want ErrSessionNotFound, got %v", err)
	}
}

// TestSessionRefreshRefusesRevoked is the revoked half of the same
// invariant: a revoked session can't be resurrected by Refresh.
func TestSessionRefreshRefusesRevoked(t *testing.T) {
	_, rdb := newTestClient(t)
	sm := NewSessionManager(rdb, WithSessionTTL(time.Hour))
	ctx := context.Background()

	sess, err := sm.Create(ctx, "dave")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Mark revoked directly in the hash (an admin SetStatus path).
	if err := rdb.HSet(ctx, sessionKey(sess.ID), "revoked", "1").Err(); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := sm.Refresh(ctx, sess.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("refresh of revoked: want ErrSessionNotFound, got %v", err)
	}
	if _, err := sm.Get(ctx, sess.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("get of revoked: want ErrSessionNotFound, got %v", err)
	}
}

func TestSessionRefreshUnknown(t *testing.T) {
	_, rdb := newTestClient(t)
	sm := NewSessionManager(rdb)
	if _, err := sm.Refresh(context.Background(), "ghost"); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("refresh unknown: want ErrSessionNotFound, got %v", err)
	}
}

func TestSessionListByUserAndAll(t *testing.T) {
	_, rdb := newTestClient(t)
	sm := NewSessionManager(rdb, WithSessionTTL(time.Hour))
	ctx := context.Background()

	s1, _ := sm.Create(ctx, "u1")
	s2, _ := sm.Create(ctx, "u1")
	_, _ = sm.Create(ctx, "u2")

	byUser, err := sm.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("list by user: %v", err)
	}
	if len(byUser) != 2 {
		t.Fatalf("list by user: want 2, got %d", len(byUser))
	}

	all, err := sm.ListAll(ctx)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("list all: want 3, got %d", len(all))
	}

	// Destroy one; index self-trims on the next list.
	if err := sm.Destroy(ctx, s1.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	byUser, _ = sm.ListByUser(ctx, "u1")
	if len(byUser) != 1 || byUser[0].ID != s2.ID {
		t.Fatalf("list after destroy: %+v", byUser)
	}
}
