package defaultimpl

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

// Part 1 — exp-bounded deny-set. White-box (package defaultimpl) so the tests
// can read each issuer's unexported `revoked` map + `revokedMu` directly to
// prove the map is bounded (entries pruned) without an exported accessor that
// would pollute the public API.

// ed25519RevokedLen reads the deny-set size under the issuer's lock.
func ed25519RevokedLen(j *Ed25519JWTIssuer) int {
	j.revokedMu.RLock()
	defer j.revokedMu.RUnlock()
	return len(j.revoked)
}

func ecdsaRevokedLen(j *ECDSAJWTIssuer) int {
	j.revokedMu.RLock()
	defer j.revokedMu.RUnlock()
	return len(j.revoked)
}

func rsaRevokedLen(j *RSAJWTIssuer) int {
	j.revokedMu.RLock()
	defer j.revokedMu.RUnlock()
	return len(j.revoked)
}

// waitPastSecond blocks until the wall clock is in a unix SECOND strictly after
// ref's second, so a token whose exp ≈ ref's second is genuinely past-exp by
// the time it returns. Bounded so a flaky clock can't hang the test forever.
func waitPastSecond(t *testing.T, ref time.Time) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Unix() <= ref.Unix() {
		if time.Now().After(deadline) {
			t.Fatal("clock did not advance past the reference second")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPruneRevoked_NeverDropsLiveEntry is the prune-not-early safety gate at
// the helper level: an entry whose exp is at or after the prune instant is
// NEVER dropped (dropping it would let a still-valid revoked token validate
// again). Only strictly-past entries go.
func TestPruneRevoked_NeverDropsLiveEntry(t *testing.T) {
	now := int64(1_000_000)
	m := map[string]int64{
		"past":   now - 1, // strictly before now -> droppable
		"exact":  now,     // exactly now -> retained (>= now)
		"future": now + 1, // after now -> retained
		"zero":   0,       // no exp -> droppable (defensive)
	}
	pruneRevoked(m, now)

	if _, ok := m["past"]; ok {
		t.Error("past-exp entry should be pruned")
	}
	if _, ok := m["zero"]; ok {
		t.Error("zero-exp entry should be pruned")
	}
	if _, ok := m["exact"]; !ok {
		t.Error("entry expiring exactly at the prune instant must be RETAINED (prune-not-early)")
	}
	if _, ok := m["future"]; !ok {
		t.Error("future-exp entry must be RETAINED (prune-not-early)")
	}
}

// TestEd25519Revoke_HonoredUpToExp proves a revoked entry is honored right up
// to (and past, until exp) the token's exp, and that a far-past-exp entry is
// pruned out of the deny-set (memory bounded) on a subsequent Revoke while a
// not-yet-expired one is NOT.
func TestEd25519Revoke_HonoredUpToExp(t *testing.T) {
	ctx := context.Background()
	// Generous skew so the not-yet-expired revoked token still validates as
	// "not expired" while we assert the deny-set rejects it FIRST.
	iss := NewEd25519JWTIssuer(WithEd25519MaxClockSkew(time.Hour))

	// A live token with a comfortably-future exp.
	live, err := iss.Issue(ctx, &sso.Subject{ID: "u-live", TTL: time.Hour}, nil)
	if err != nil {
		t.Fatalf("issue live: %v", err)
	}
	if err := iss.Revoke(ctx, live.AccessToken); err != nil {
		t.Fatalf("revoke live: %v", err)
	}
	// The revoked-but-not-yet-expired token must be REJECTED by Validate — its
	// revocation is honored right up to its exp.
	if _, err := iss.Validate(ctx, live.AccessToken); err == nil {
		t.Fatal("a revoked token must be rejected by Validate before its exp")
	}
	if n := ed25519RevokedLen(iss); n != 1 {
		t.Fatalf("deny-set should hold the live revoked entry, have %d", n)
	}

	// A token that is already past its exp (issued with a tiny TTL). Revoke it:
	// markRevoked records it then immediately prunes — its exp is in the past,
	// so it must NOT linger in the deny-set (memory bounded). The live entry
	// above must SURVIVE the same prune (prune-not-early).
	beforeStale := time.Now()
	stale, err := iss.Issue(ctx, &sso.Subject{ID: "u-stale", TTL: time.Nanosecond}, nil)
	if err != nil {
		t.Fatalf("issue stale: %v", err)
	}
	// exp is unix SECONDS (≈ the issue second for a nanosecond TTL), so wait
	// until the wall clock crosses STRICTLY past beforeStale's second — only
	// then is the stale deny-set entry genuinely past-exp and droppable. (A
	// token issued in the current second has exp == now-second and is correctly
	// RETAINED by prune-not-early.)
	waitPastSecond(t, beforeStale)
	// Revoke calls Validate first; with the large skew the stale token still
	// passes the expiry check, so Revoke succeeds and records it — then prune
	// drops it because its exp < now.
	if err := iss.Revoke(ctx, stale.AccessToken); err != nil {
		t.Fatalf("revoke stale: %v", err)
	}
	if n := ed25519RevokedLen(iss); n != 1 {
		t.Fatalf("stale (past-exp) entry must be pruned, leaving only the live entry; have %d", n)
	}
	// And the live entry is still honored after the prune swept the stale one.
	if _, err := iss.Validate(ctx, live.AccessToken); err == nil {
		t.Fatal("live revoked entry must survive the prune (prune-not-early) and still reject")
	}
}

func TestECDSARevoke_HonoredUpToExp(t *testing.T) {
	ctx := context.Background()
	iss := NewECDSAJWTIssuer(WithECDSAMaxClockSkew(time.Hour))

	live, err := iss.Issue(ctx, &sso.Subject{ID: "u-live", TTL: time.Hour}, nil)
	if err != nil {
		t.Fatalf("issue live: %v", err)
	}
	if err := iss.Revoke(ctx, live.AccessToken); err != nil {
		t.Fatalf("revoke live: %v", err)
	}
	if _, err := iss.Validate(ctx, live.AccessToken); err == nil {
		t.Fatal("a revoked token must be rejected by Validate before its exp")
	}
	if n := ecdsaRevokedLen(iss); n != 1 {
		t.Fatalf("deny-set should hold the live revoked entry, have %d", n)
	}

	beforeStale := time.Now()
	stale, err := iss.Issue(ctx, &sso.Subject{ID: "u-stale", TTL: time.Nanosecond}, nil)
	if err != nil {
		t.Fatalf("issue stale: %v", err)
	}
	waitPastSecond(t, beforeStale)
	if err := iss.Revoke(ctx, stale.AccessToken); err != nil {
		t.Fatalf("revoke stale: %v", err)
	}
	if n := ecdsaRevokedLen(iss); n != 1 {
		t.Fatalf("stale (past-exp) entry must be pruned; have %d", n)
	}
	if _, err := iss.Validate(ctx, live.AccessToken); err == nil {
		t.Fatal("live revoked entry must survive the prune and still reject")
	}
}

func TestRSARevoke_HonoredUpToExp(t *testing.T) {
	ctx := context.Background()
	iss := NewRSAJWTIssuer(WithRSAMaxClockSkew(time.Hour))

	live, err := iss.Issue(ctx, &sso.Subject{ID: "u-live", TTL: time.Hour}, nil)
	if err != nil {
		t.Fatalf("issue live: %v", err)
	}
	if err := iss.Revoke(ctx, live.AccessToken); err != nil {
		t.Fatalf("revoke live: %v", err)
	}
	if _, err := iss.Validate(ctx, live.AccessToken); err == nil {
		t.Fatal("a revoked token must be rejected by Validate before its exp")
	}
	if n := rsaRevokedLen(iss); n != 1 {
		t.Fatalf("deny-set should hold the live revoked entry, have %d", n)
	}

	beforeStale := time.Now()
	stale, err := iss.Issue(ctx, &sso.Subject{ID: "u-stale", TTL: time.Nanosecond}, nil)
	if err != nil {
		t.Fatalf("issue stale: %v", err)
	}
	waitPastSecond(t, beforeStale)
	if err := iss.Revoke(ctx, stale.AccessToken); err != nil {
		t.Fatalf("revoke stale: %v", err)
	}
	if n := rsaRevokedLen(iss); n != 1 {
		t.Fatalf("stale (past-exp) entry must be pruned; have %d", n)
	}
	if _, err := iss.Validate(ctx, live.AccessToken); err == nil {
		t.Fatal("live revoked entry must survive the prune and still reject")
	}
}
