package redis

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

func TestSessionCreateGetDestroy(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	_, rdb := newTestClient(t)
	sm := NewSessionManager(rdb)
	if _, err := sm.Get(context.Background(), "nope"); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("get unknown: want ErrSessionNotFound, got %v", err)
	}
}

// TestSessionRefreshExtends locks the happy path: a live session extends.
func TestSessionRefreshExtends(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// TestSessionRefreshMillisBoundary is the precision proof for the §2
// "captured expired session id can't be resurrected" invariant at the
// EXACT expiry boundary. expires_at is stored + compared as Unix
// MILLISECONDS; the refresh script's `tonumber(expires_at) <= tonumber(now)`
// runs in Lua float64, which holds a ~1.7e12 ms value EXACTLY — so a now of
// expires_at-1ms is allowed (live) and expires_at+1ms is refused (expired),
// to single-millisecond resolution.
//
// The pre-fix code stored Unix NANOSECONDS (~1.7e18), which overflows
// float64's 53-bit exact-integer range (2^53 ~= 9e15) by ~190x: the last
// ~8 bits round, so two ns timestamps 1ns (or even ~190ns) apart can compare
// EQUAL, blurring the boundary and potentially extending a just-expired
// session. We drive the script directly with controlled ARGV (Refresh reads
// wall-clock time.Now() internally, so direct invocation is the only way to
// pin `now` to the boundary deterministically).
func TestSessionRefreshMillisBoundary(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()

	// A session whose deadline is a precise, large (realistic) Unix-ms value
	// — large enough that the ns-encoded equivalent would lose precision.
	const expiresMs = int64(1_700_000_000_123) // ~2023-11-14, .123s
	key := sessionKey("boundary")
	if err := rdb.HSet(ctx, key,
		"user_id", "erin",
		"created_at", strconv.FormatInt(expiresMs-3600_000, 10),
		"expires_at", strconv.FormatInt(expiresMs, 10),
		"revoked", "0",
	).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ttlSecs := int64(3600)

	// now = expires_at - 1ms: still live -> script extends (returns new exp).
	res, err := refreshScript.Run(ctx, rdb, []string{key},
		expiresMs-1, expiresMs+ttlSecs*1000, ttlSecs).Int64()
	if err != nil {
		t.Fatalf("refresh at -1ms: %v", err)
	}
	if res < 0 {
		t.Fatalf("at expires_at-1ms: want allowed (live), got refused (%d)", res)
	}

	// Reset the deadline (the prior run advanced it) and probe +1ms.
	if err := rdb.HSet(ctx, key, "expires_at", strconv.FormatInt(expiresMs, 10)).Err(); err != nil {
		t.Fatalf("reset exp: %v", err)
	}
	res, err = refreshScript.Run(ctx, rdb, []string{key},
		expiresMs+1, expiresMs+ttlSecs*1000, ttlSecs).Int64()
	if err != nil {
		t.Fatalf("refresh at +1ms: %v", err)
	}
	if res >= 0 {
		t.Fatalf("at expires_at+1ms: want refused (expired), got allowed (%d)", res)
	}

	// And exactly AT the boundary: `<=` means now==expires_at is refused.
	if err := rdb.HSet(ctx, key, "expires_at", strconv.FormatInt(expiresMs, 10)).Err(); err != nil {
		t.Fatalf("reset exp: %v", err)
	}
	res, err = refreshScript.Run(ctx, rdb, []string{key},
		expiresMs, expiresMs+ttlSecs*1000, ttlSecs).Int64()
	if err != nil {
		t.Fatalf("refresh at boundary: %v", err)
	}
	if res >= 0 {
		t.Fatalf("at expires_at exactly: want refused, got allowed (%d)", res)
	}
}

// TestSessionRefreshNearExpiryPublicAPI exercises the same boundary through
// the public Refresh API (not the raw script): a session whose stored
// expires_at is a hair in the FUTURE refreshes; a hair in the PAST is
// refused as ErrSessionNotFound. Uses a comfortable margin (50ms) so the
// wall-clock read inside Refresh can't straddle the boundary and flake,
// while still proving millis round-trips correctly end to end.
func TestSessionRefreshNearExpiryPublicAPI(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	sm := NewSessionManager(rdb, WithSessionTTL(time.Hour))
	ctx := context.Background()

	sess, err := sm.Create(ctx, "frank")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Pin expires_at just AFTER now -> Refresh must extend.
	future := time.Now().Add(50 * time.Millisecond)
	if err := rdb.HSet(ctx, sessionKey(sess.ID),
		"expires_at", strconv.FormatInt(future.UnixMilli(), 10)).Err(); err != nil {
		t.Fatalf("set future exp: %v", err)
	}
	if _, err := sm.Refresh(ctx, sess.ID); err != nil {
		t.Fatalf("refresh of just-live session: want ok, got %v", err)
	}

	// Pin expires_at just BEFORE now -> Refresh must refuse.
	past := time.Now().Add(-50 * time.Millisecond)
	if err := rdb.HSet(ctx, sessionKey(sess.ID),
		"expires_at", strconv.FormatInt(past.UnixMilli(), 10)).Err(); err != nil {
		t.Fatalf("set past exp: %v", err)
	}
	if _, err := sm.Refresh(ctx, sess.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("refresh of just-expired session: want ErrSessionNotFound, got %v", err)
	}
}

func TestSessionRefreshUnknown(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	sm := NewSessionManager(rdb)
	if _, err := sm.Refresh(context.Background(), "ghost"); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("refresh unknown: want ErrSessionNotFound, got %v", err)
	}
}

func TestSessionListByUserAndAll(t *testing.T) {
	t.Parallel()
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
