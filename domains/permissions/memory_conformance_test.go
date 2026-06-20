package permissions_test

import (
	"testing"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/domains/permissions/permissionstest"
)

// TestMemoryProvider_Conformance runs the shared Provider conformance
// suite against the in-memory peer. Locked-in equivalence with the
// SQLite peer (see permissions/sqlite tests) is the whole point —
// operators swapping backends should see no behavior differences.
func TestMemoryProvider_Conformance(t *testing.T) {
	permissionstest.ConformanceSuite{
		Factory: func(_ *testing.T) permissions.Provider {
			return permissions.NewMemoryProvider()
		},
	}.Run(t)
}
