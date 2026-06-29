package idp

import (
	"testing"

	"github.com/snaplink/sso/saml/samltest"
)

// TestLogoutReplayConformance_Memory runs the shared replay-dedup conformance
// suite against the in-memory logoutReplayStore (the IdP default). The sqlite
// peer runs the SAME suite in saml/idp/sqlite, locking the two backends to
// identical dedup behavior. (samltest imports neither idp nor sp, so this
// INTERNAL `package idp` test introduces no import cycle.)
func TestLogoutReplayConformance_Memory(t *testing.T) {
	t.Parallel()
	samltest.ReplayConformance{
		Factory: func(t *testing.T) samltest.ReplayChecker {
			return newLogoutReplayStore(0)
		},
	}.Run(t)
}
