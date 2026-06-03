package redis

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/oauth"
)

func newRTInfo(user, client, family string) *oauth.RefreshToken {
	now := time.Now()
	return &oauth.RefreshToken{
		UserID:    user,
		ClientID:  client,
		Scopes:    []string{"openid"},
		FamilyID:  family,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
}

func TestRefreshIssueConsume(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	if err := s.Issue(ctx, "rt1", newRTInfo("alice", "app", "fam1")); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Consume(ctx, "rt1")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.UserID != "alice" || got.ClientID != "app" || got.FamilyID != "fam1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestRefreshOracleLeak: unknown / expired collapse to ErrRefreshTokenNotFound.
// (Already-consumed WITH a family is reuse — tested separately; an opt-out
// token with no family that's re-consumed is plain not-found, covered here.)
func TestRefreshOracleLeak(t *testing.T) {
	mr, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	// 1. Unknown.
	if _, err := s.Consume(ctx, "ghost"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("unknown: want ErrRefreshTokenNotFound, got %v", err)
	}

	// 2. Expired.
	info := newRTInfo("bob", "app", "")
	info.ExpiresAt = time.Now().Add(time.Second)
	_ = s.Issue(ctx, "stale", info)
	mr.FastForward(2 * time.Second)
	if _, err := s.Consume(ctx, "stale"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("expired: want ErrRefreshTokenNotFound, got %v", err)
	}

	// 3. Opt-out (empty family) re-consume = plain not-found, no reuse signal.
	_ = s.Issue(ctx, "noFam", newRTInfo("bob", "app", ""))
	if _, err := s.Consume(ctx, "noFam"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.Consume(ctx, "noFam"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("opt-out re-consume: want ErrRefreshTokenNotFound, got %v", err)
	}
}

// TestRefreshSingleUseRace: one winner among N concurrent Consume.
func TestRefreshSingleUseRace(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()
	_ = s.Issue(ctx, "hot", newRTInfo("alice", "app", "fam"))

	const n = 16
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { _, err := s.Consume(ctx, "hot"); results <- err }()
	}
	wins, reuses := 0, 0
	for i := 0; i < n; i++ {
		err := <-results
		switch {
		case err == nil:
			wins++
		case errors.Is(err, oauth.ErrRefreshTokenReused):
			reuses++ // a loser that raced after the marker was stamped
		case errors.Is(err, oauth.ErrRefreshTokenNotFound):
			// loser before the marker was stamped — also fine
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("single-use violated: %d winners, want 1", wins)
	}
}

// TestRefreshFamilyRotationAndReuse is the BCP §4.13 invariant: a token
// carried through rotations shares the FamilyID; replaying a consumed
// (rotated-away) token is detected as reuse, returning ErrRefreshTokenReused
// with the FamilyID so the handler can DeleteFamily.
func TestRefreshFamilyRotationAndReuse(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	// Issue + rotate: rt-a -> rt-b -> rt-c, all family "F".
	_ = s.Issue(ctx, "rt-a", newRTInfo("alice", "app", "F"))
	if _, err := s.Consume(ctx, "rt-a"); err != nil {
		t.Fatalf("consume rt-a: %v", err)
	}
	_ = s.Issue(ctx, "rt-b", newRTInfo("alice", "app", "F"))
	if _, err := s.Consume(ctx, "rt-b"); err != nil {
		t.Fatalf("consume rt-b: %v", err)
	}
	_ = s.Issue(ctx, "rt-c", newRTInfo("alice", "app", "F"))

	// Replay the already-consumed rt-a: must be reuse with FamilyID "F".
	got, err := s.Consume(ctx, "rt-a")
	if !errors.Is(err, oauth.ErrRefreshTokenReused) {
		t.Fatalf("replay rt-a: want ErrRefreshTokenReused, got %v", err)
	}
	if got == nil || got.FamilyID != "F" {
		t.Fatalf("reuse must carry FamilyID F, got %+v", got)
	}

	// Handler reacts by killing the family. rt-c (the still-active leaf)
	// must die; the count reflects active tokens removed.
	n, err := s.DeleteFamily(ctx, "F")
	if err != nil {
		t.Fatalf("delete family: %v", err)
	}
	if n != 1 {
		t.Fatalf("DeleteFamily count: want 1 active (rt-c), got %d", n)
	}
	if _, err := s.Consume(ctx, "rt-c"); errors.Is(err, oauth.ErrRefreshTokenReused) {
		// rt-c had a consumed marker? no — it was active. After DeleteFamily
		// its marker is wiped too, so it's a plain not-found.
		t.Fatalf("rt-c after DeleteFamily: should be plain not-found, got reuse")
	} else if !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("rt-c after DeleteFamily: want ErrRefreshTokenNotFound, got %v", err)
	}
}

// TestRefreshConcurrentIssueBulkRevoke guards FIX 2: indexAdd's SADD +
// EXPIRE must be atomic AND only-extending. Many tokens with VARYING TTLs
// are issued to the SAME (subject, client) concurrently; the per-subject
// index TTL must end up >= the LONGEST token TTL, never shortened by a
// racing shorter Expire. Then DeleteAllForSubject must find + remove EVERY
// still-active token — a shortened index TTL would GC the index early and
// silently miss some, breaking bulk revocation + the compliance Eraser.
//
// Pre-fix (SADD then Expire as two ops) this could flake: a short-TTL
// Issue's Expire landing last would clamp the index, dropping ids and
// returning < N from DeleteAllForSubject.
func TestRefreshConcurrentIssueBulkRevoke(t *testing.T) {
	_, rdb := newTestClient(t)
	// Small familyTTL so the index TTL is governed by the token TTLs, not a
	// large floor — that's what makes a shortened-TTL race observable.
	s := NewRefreshTokenStore(rdb, WithFamilyTTL(time.Second))
	ctx := context.Background()

	const n = 60
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			info := newRTInfo("zoe", "app", fmt.Sprintf("F%d", i))
			// Varying TTLs: a spread from short to long, issued concurrently.
			info.ExpiresAt = time.Now().Add(time.Duration(i+1) * time.Minute)
			if err := s.Issue(ctx, fmt.Sprintf("tok-%d", i), info); err != nil {
				t.Errorf("issue %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	// The per-subject index TTL must be at least the longest token TTL
	// (~n minutes). If a racing shorter Expire had won, this would be far
	// smaller (down toward 1 minute / familyTTL).
	idxKey := rtSubjectKey("zoe", "app")
	ttl, err := rdb.TTL(ctx, idxKey).Result()
	if err != nil {
		t.Fatalf("index ttl: %v", err)
	}
	if ttl < (n-1)*time.Minute {
		t.Fatalf("index TTL was shortened: got %v, want >= %v", ttl, (n-1)*time.Minute)
	}

	// Bulk revocation must find + remove ALL n active tokens.
	removed, err := s.DeleteAllForSubject(ctx, "zoe", "app")
	if err != nil {
		t.Fatalf("delete all for subject: %v", err)
	}
	if removed != n {
		t.Fatalf("bulk revoke missed tokens: removed %d, want %d", removed, n)
	}
	// Confirm every token is actually gone.
	for i := 0; i < n; i++ {
		if _, err := s.Consume(ctx, fmt.Sprintf("tok-%d", i)); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
			t.Fatalf("tok-%d survived bulk revoke: %v", i, err)
		}
	}
}

// TestRefreshFamilyReuseNeverConsumed guards FIX 3: the family-membership
// ledger is written at ISSUE (mirroring SQLite), so a token whose active
// key is GONE WITHOUT EVER BEING CONSUMED (e.g. TTL-evicted) is still
// recognized as a family member on replay and triggers ErrRefreshTokenReused
// + the FamilyID — matching the SQLite peer. Pre-fix the Redis marker was
// only written at Consume, so an evicted-never-consumed token lost reuse
// detection (degraded to plain not-found), weakening BCP §4.13 family-kill
// for that class.
//
// We simulate the active key vanishing without a Consume by DELeting just
// rtKey(token) while leaving the issue-time membership marker intact (the
// realistic case is a silent TTL eviction of the active key, whose marker
// outlives it by familyTTL).
func TestRefreshFamilyReuseNeverConsumed(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	// Issue with a family; do NOT Consume it.
	if err := s.Issue(ctx, "ghost-tok", newRTInfo("alice", "app", "FAM")); err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Active key disappears without a Consume (TTL eviction analogue): the
	// issue-time membership marker remains.
	if err := rdb.Del(ctx, rtKey("ghost-tok")).Err(); err != nil {
		t.Fatalf("evict active key: %v", err)
	}

	// First presentation after the active key is gone: must be detected as
	// reuse with the family, NOT plain not-found.
	got, err := s.Consume(ctx, "ghost-tok")
	if !errors.Is(err, oauth.ErrRefreshTokenReused) {
		t.Fatalf("evicted-never-consumed replay: want ErrRefreshTokenReused, got %v", err)
	}
	if got == nil || got.FamilyID != "FAM" {
		t.Fatalf("reuse must carry FamilyID FAM, got %+v", got)
	}

	// A second presentation is likewise reuse (the marker is a stable ledger,
	// not a single-use gate) — matches SQLite, and never a redeem path.
	got2, err := s.Consume(ctx, "ghost-tok")
	if !errors.Is(err, oauth.ErrRefreshTokenReused) || got2 == nil || got2.FamilyID != "FAM" {
		t.Fatalf("second replay: want reuse+FAM, got %+v err=%v", got2, err)
	}

	// The empty-FamilyID opt-out still degrades to plain not-found even when
	// the active key vanishes without a Consume (no marker was written).
	if err := s.Issue(ctx, "ghost-nofam", newRTInfo("alice", "app", "")); err != nil {
		t.Fatalf("issue nofam: %v", err)
	}
	if err := rdb.Del(ctx, rtKey("ghost-nofam")).Err(); err != nil {
		t.Fatalf("evict nofam: %v", err)
	}
	if _, err := s.Consume(ctx, "ghost-nofam"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("opt-out evicted replay: want ErrRefreshTokenNotFound, got %v", err)
	}
}

func TestRefreshInspectAndDelete(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()
	_ = s.Issue(ctx, "rt", newRTInfo("alice", "app", "F"))

	got, err := s.Inspect(ctx, "rt")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if got.UserID != "alice" {
		t.Fatalf("inspect mismatch: %+v", got)
	}
	// Inspect is non-destructive: a Consume still works.
	if _, err := s.Consume(ctx, "rt"); err != nil {
		t.Fatalf("consume after inspect: %v", err)
	}

	// Delete is idempotent on unknown tokens.
	if err := s.Delete(ctx, "never"); err != nil {
		t.Fatalf("delete unknown: %v", err)
	}
	if _, err := s.Inspect(ctx, "never"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("inspect unknown: want ErrRefreshTokenNotFound, got %v", err)
	}
}

func TestRefreshSubjectIndexAndCount(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	_ = s.Issue(ctx, "a1", newRTInfo("alice", "app1", "F1"))
	_ = s.Issue(ctx, "a2", newRTInfo("alice", "app1", "F2"))
	_ = s.Issue(ctx, "a3", newRTInfo("alice", "app2", "F3"))
	_ = s.Issue(ctx, "b1", newRTInfo("bob", "app1", "F4"))

	// Count for (alice, app1) = 2.
	if n, err := s.CountForSubject(ctx, "alice", "app1"); err != nil || n != 2 {
		t.Fatalf("count alice/app1: n=%d err=%v want 2", n, err)
	}
	// Count for alice across all clients = 3.
	if n, err := s.CountForSubject(ctx, "alice", ""); err != nil || n != 3 {
		t.Fatalf("count alice/*: n=%d err=%v want 3", n, err)
	}

	// Delete (alice, app1) -> 2 removed.
	if n, err := s.DeleteAllForSubject(ctx, "alice", "app1"); err != nil || n != 2 {
		t.Fatalf("delete alice/app1: n=%d err=%v want 2", n, err)
	}
	if _, err := s.Consume(ctx, "a1"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("a1 should be gone")
	}
	// alice/app2 + bob/app1 survive.
	if _, err := s.Consume(ctx, "a3"); err != nil {
		t.Fatalf("a3 (alice/app2) should survive: %v", err)
	}
	if _, err := s.Consume(ctx, "b1"); err != nil {
		t.Fatalf("b1 (bob/app1) should survive: %v", err)
	}

	// Delete-all across clients for alice (re-issue a2 lookalike).
	_ = s.Issue(ctx, "a4", newRTInfo("alice", "app2", "F5"))
	if n, err := s.DeleteAllForSubject(ctx, "alice", ""); err != nil || n != 1 {
		// only a4 remains active (a2 was app1, already wiped; a3 consumed above)
		t.Fatalf("delete alice/*: n=%d err=%v want 1", n, err)
	}
}

func TestRefreshClientPurger(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	ctx := context.Background()

	_ = s.Issue(ctx, "c1", newRTInfo("alice", "tenantApp", "F1"))
	_ = s.Issue(ctx, "c2", newRTInfo("bob", "tenantApp", "F2"))
	_ = s.Issue(ctx, "c3", newRTInfo("carol", "otherApp", "F3"))

	// Empty clientID is a NO-OP (not a wildcard).
	if n, err := s.DeleteAllForClient(ctx, ""); err != nil || n != 0 {
		t.Fatalf("empty client purge: n=%d err=%v want 0", n, err)
	}

	n, err := s.DeleteAllForClient(ctx, "tenantApp")
	if err != nil || n != 2 {
		t.Fatalf("purge tenantApp: n=%d err=%v want 2", n, err)
	}
	if _, err := s.Consume(ctx, "c1"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("c1 should be purged")
	}
	if _, err := s.Consume(ctx, "c3"); err != nil {
		t.Fatalf("c3 (otherApp) should survive: %v", err)
	}
}
