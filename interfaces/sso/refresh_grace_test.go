package sso

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/internal/handler/tokengrant"
)

func TestRefreshGraceCache(t *testing.T) {
	t.Parallel()
	c := tokengrant.NewRefreshGraceCache(time.Minute)
	now := time.Now()
	resp := map[string]any{"access_token": "a1", "refresh_token": "r2"}
	c.Remember("old", resp, now)

	// Within window -> hit, returning a COPY of the successor.
	got, ok := c.Lookup("old", now.Add(30*time.Second))
	if !ok {
		t.Fatal("expected a grace hit within the window")
	}
	if got["access_token"] != "a1" || got["refresh_token"] != "r2" {
		t.Errorf("cached successor mismatch: %v", got)
	}
	// Mutating the returned map must NOT corrupt the cache.
	got["access_token"] = "tampered"
	if again, _ := c.Lookup("old", now.Add(30*time.Second)); again["access_token"] != "a1" {
		t.Error("lookup returned an aliased map — cache was corrupted")
	}

	// After the window -> miss (expired exactly-at boundary counts as expired).
	if _, ok := c.Lookup("old", now.Add(time.Minute)); ok {
		t.Error("expected a grace miss at/after the window boundary")
	}
	// Unknown token -> miss.
	if _, ok := c.Lookup("never", now); ok {
		t.Error("unknown token should miss")
	}

	// nil receiver + empty token are safe no-ops.
	var nilC *tokengrant.RefreshGraceCache
	if _, ok := nilC.Lookup("x", now); ok {
		t.Error("nil cache lookup should miss")
	}
	nilC.Remember("x", resp, now) // must not panic
	c.Remember("", resp, now)     // empty token ignored
	if _, ok := c.Lookup("", now); ok {
		t.Error("empty token should never be cached")
	}
}
