package sp

import (
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// TestReplayExpiry_NoDeadlineUsesClockSeam proves the no-explicit-deadline
// fallback uses the SUPPLIED clock (the seam ProcessAssertion threads through),
// not wall-clock time.Now() -- so the replay-store prune stays deterministic
// under a pinned test clock and never mixes a pinned now with the real clock.
// Pinning to the year 2000 makes a wall-clock regression obvious (it would
// return ~now, not 2000).
func TestReplayExpiry_NoDeadlineUsesClockSeam(t *testing.T) {
	t.Parallel()
	pinned := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	// An assertion with neither Conditions.NotOnOrAfter nor a
	// SubjectConfirmationData.NotOnOrAfter exercises the fallback branch.
	got := replayExpiry(&saml.Assertion{}, pinned)
	want := pinned.Add(5 * time.Minute)
	if !got.Equal(want) {
		t.Fatalf("replayExpiry(no-deadline) = %v, want %v (must use the supplied clock seam, not time.Now())", got, want)
	}

	// A present Conditions deadline still wins over the fallback.
	withCond := &saml.Assertion{Conditions: &saml.Conditions{NotOnOrAfter: pinned.Add(time.Minute)}}
	if got := replayExpiry(withCond, pinned); !got.Equal(pinned.Add(time.Minute)) {
		t.Fatalf("replayExpiry(with Conditions) = %v, want %v", got, pinned.Add(time.Minute))
	}
}
