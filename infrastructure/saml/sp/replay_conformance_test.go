package sp

import (
	"testing"

	"github.com/snaplink/sso/saml/samltest"
)

// TestReplayConformance_Memory runs the shared replay-dedup conformance suite
// against the in-memory replayStore (the SP's default for BOTH the assertion and
// the SP-side-logout replay caches — same type). The sqlite peer runs the SAME
// suite in saml/sp/sqlite, so the two backends are locked to identical dedup
// behavior.
func TestReplayConformance_Memory(t *testing.T) {
	samltest.ReplayConformance{
		Factory: func(t *testing.T) samltest.ReplayChecker {
			return newReplayStore(0)
		},
	}.Run(t)
}
