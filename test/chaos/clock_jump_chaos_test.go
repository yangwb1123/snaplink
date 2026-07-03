//go:build chaos

package chaostest

import (
	"testing"
	"time"

	"github.com/snaplink/sso/internal/handler/tokengrant"
)

// TestChaos_RefreshGrace_ForwardClockJumpExpiresWindow exercises the ONE
// injectable-clock seam already in the refresh double-submit grace cache
// (internal/handler/tokengrant.RefreshGraceCache): every Remember/Lookup call
// takes an explicit `now time.Time` instead of reading time.Now() itself. A
// forward clock jump (NTP step correction, a paused-then-resumed VM/container)
// between Remember and Lookup must behave EXACTLY as if that much wall time
// had genuinely elapsed — the grace window must not survive it, or a
// double-submit replay could stay "fresh" far longer than intended.
func TestChaos_RefreshGrace_ForwardClockJumpExpiresWindow(t *testing.T) {
	cache := tokengrant.NewRefreshGraceCache(2 * time.Second)
	base := time.Now()
	cache.Remember("chaos-rotated-token", map[string]any{"access_token": "a1"}, base)

	// Within the window: a benign near-simultaneous double-submit still
	// replays the cached successor.
	if _, ok := cache.Lookup("chaos-rotated-token", base.Add(500*time.Millisecond)); !ok {
		t.Fatal("expected a hit well inside the grace window")
	}

	// The clock jumps forward well past the window (e.g. an NTP step or a
	// container thaw) — the entry MUST now read as expired, exactly like a
	// genuine post-window replay falling through to family-reuse detection.
	jumped := base.Add(time.Hour)
	if _, ok := cache.Lookup("chaos-rotated-token", jumped); ok {
		t.Fatal("grace entry survived a forward clock jump past its window")
	}
}

// TestChaos_RefreshGrace_BackwardClockStepDoesNotExtendWindow covers the
// opposite fault: the system clock steps BACKWARD (a bad NTP correction, a
// hypervisor clock rollback) between Remember and the eventual prune. Lookup
// anchors expiry off the `now` passed to Remember, so a later Lookup call
// timestamped BEFORE that anchor must still see the entry as live (an
// in-window replay must never spuriously fail closed just because the local
// clock briefly went backward) — but it must NOT let repeated backward steps
// keep re-arming an already-consumed grace window indefinitely, since
// Remember (not Lookup) is what sets expires.
func TestChaos_RefreshGrace_BackwardClockStepDoesNotExtendWindow(t *testing.T) {
	cache := tokengrant.NewRefreshGraceCache(time.Second)
	base := time.Now()
	cache.Remember("chaos-rotated-token-2", map[string]any{"access_token": "a2"}, base)

	// Clock steps backward relative to `base` but is still inside the window
	// anchored at Remember-time — must be a hit (Lookup never widens or
	// narrows the window; it only compares against the stored expiry).
	steppedBack := base.Add(-time.Minute)
	if _, ok := cache.Lookup("chaos-rotated-token-2", steppedBack); !ok {
		t.Fatal("expected a hit when now is before the Remember anchor (window unaffected by a backward step)")
	}

	// A second Remember for a DIFFERENT token at the stepped-back time must
	// anchor ITS OWN expiry off the stepped-back clock, not silently inherit
	// or extend the first entry's window.
	cache.Remember("chaos-rotated-token-3", map[string]any{"access_token": "a3"}, steppedBack)
	if _, ok := cache.Lookup("chaos-rotated-token-3", steppedBack.Add(2*time.Second)); ok {
		t.Fatal("second entry's window should have expired relative to ITS OWN Remember anchor")
	}
}
