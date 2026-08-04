package routertest

import (
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// TestConformanceSuite_StdRouter is the suite's self-smoke AND the StdRouter
// backend hookup. StdRouter is the reference implementation the suite's
// byte-identity contract derives from (http.NotFound), so it must pass
// green; a failure here means the suite itself is broken, not a backend.
// (The hookup cannot live in shared/core/router_test.go: that file is
// package core, and an internal test of core importing routertest — which
// imports core — would be an import cycle.)
func TestConformanceSuite_StdRouter(t *testing.T) {
	ConformanceSuite{Factory: func(t *testing.T) core.Router {
		return core.NewStdRouter()
	}}.Run(t)
}
