package tokengrant

import (
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// TestTokExSubject_SenderConstraint locks RFC 9449 / RFC 8705: the exchanged
// access token's Subject carries the captured DPoP JKT / mTLS x5t#S256, so a
// sender-constrained token-exchange yields a cnf-bound token (previously the
// token-exchange grant alone dropped the binding, issuing an unbound token).
func TestTokExSubject_SenderConstraint(t *testing.T) {
	client := &core.Client{ID: "rp"}

	bound := tokExSubject(client, &tokExState{
		claims:    &core.TokenClaims{Subject: "alice"},
		issuedSub: "alice",
		confJKT:   "jkt-abc",
		confX5T:   "x5t-def",
	})
	if bound.ConfirmationJKT != "jkt-abc" || bound.ConfirmationX5TS256 != "x5t-def" {
		t.Fatalf("sender constraint not bound onto the exchanged token: jkt=%q x5t=%q",
			bound.ConfirmationJKT, bound.ConfirmationX5TS256)
	}

	// No proof presented -> the exchanged token stays unbound (unchanged).
	plain := tokExSubject(client, &tokExState{
		claims:    &core.TokenClaims{Subject: "alice"},
		issuedSub: "alice",
	})
	if plain.ConfirmationJKT != "" || plain.ConfirmationX5TS256 != "" {
		t.Fatalf("unbound exchange must leave cnf empty: jkt=%q x5t=%q",
			plain.ConfirmationJKT, plain.ConfirmationX5TS256)
	}
}

// TestRefreshGraceCache_RememberLookup locks the core double-submit idempotency:
// a token remembered within the window replays its cached successor, the cached
// copy is independent of both the stored input and prior reads, and unknown
// tokens miss.
func TestRefreshGraceCache_RememberLookup(t *testing.T) {
	c := NewRefreshGraceCache(time.Minute)
	now := time.Now()
	resp := map[string]any{"access_token": "AT1", "refresh_token": "RT2"}
	c.Remember("RT1", resp, now)

	// Mutating the original after Remember must not leak into the cache.
	resp["access_token"] = "TAMPERED"

	got, ok := c.Lookup("RT1", now)
	if !ok {
		t.Fatal("expected hit for remembered token within window")
	}
	if got["access_token"] != "AT1" {
		t.Fatalf("cached response corrupted by caller mutation: %v", got["access_token"])
	}

	// The returned copy must be independent of the cached entry.
	got["access_token"] = "MINE"
	again, ok := c.Lookup("RT1", now)
	if !ok || again["access_token"] != "AT1" {
		t.Fatalf("Lookup returned an aliased copy: %v", again["access_token"])
	}

	if _, ok := c.Lookup("never-cached", now); ok {
		t.Fatal("unknown token must miss")
	}
}

// TestRefreshGraceCache_TTLExpiry locks the window boundary: expired-at-exactly-
// now is treated as expired (the grace must not return after the window), and a
// lookup before the boundary still hits.
func TestRefreshGraceCache_TTLExpiry(t *testing.T) {
	window := 100 * time.Millisecond
	c := NewRefreshGraceCache(window)
	now := time.Now()
	c.Remember("RT1", map[string]any{"x": 1}, now)

	// Just inside the window.
	if _, ok := c.Lookup("RT1", now.Add(window-time.Nanosecond)); !ok {
		t.Fatal("expected hit just before expiry")
	}
	// Exactly at expiry must be treated as expired (Lookup uses now.Before).
	if _, ok := c.Lookup("RT1", now.Add(window)); ok {
		t.Fatal("expired-at-exactly-now must be treated as expired")
	}
	// Past the window.
	if _, ok := c.Lookup("RT1", now.Add(2*window)); ok {
		t.Fatal("expected miss after window")
	}
}

// TestRefreshGraceCache_Prune verifies that Remember lazily drops expired
// entries so the map stays bounded by rotation-rate x window.
func TestRefreshGraceCache_Prune(t *testing.T) {
	window := 50 * time.Millisecond
	c := NewRefreshGraceCache(window)
	t0 := time.Now()
	c.Remember("old1", map[string]any{"x": 1}, t0)
	c.Remember("old2", map[string]any{"x": 2}, t0)

	if got := mapLen(c); got != 2 {
		t.Fatalf("expected 2 entries, got %d", got)
	}

	// A later Remember past the window prunes the stale entries before insert.
	c.Remember("fresh", map[string]any{"x": 3}, t0.Add(window+time.Millisecond))
	if got := mapLen(c); got != 1 {
		t.Fatalf("expected stale entries pruned, leaving 1, got %d", got)
	}
	if _, ok := c.Lookup("fresh", t0.Add(window+time.Millisecond)); !ok {
		t.Fatal("fresh entry should remain after prune")
	}
}

// TestRefreshGraceCache_NilAndEmptyGuards locks the no-op guards: a nil cache
// and an empty token are silent no-ops on both Remember and Lookup.
func TestRefreshGraceCache_NilAndEmptyGuards(t *testing.T) {
	var nilCache *RefreshGraceCache
	now := time.Now()
	// Must not panic.
	nilCache.Remember("RT", map[string]any{"x": 1}, now)
	if _, ok := nilCache.Lookup("RT", now); ok {
		t.Fatal("nil cache Lookup must miss")
	}

	c := NewRefreshGraceCache(time.Minute)
	c.Remember("", map[string]any{"x": 1}, now)
	if _, ok := c.Lookup("", now); ok {
		t.Fatal("empty token must never be cached or looked up")
	}
}

// mapLen reads the cache's entry count under its own lock (test-local helper;
// the field is package-private and tests live in the same package).
func mapLen(c *RefreshGraceCache) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
