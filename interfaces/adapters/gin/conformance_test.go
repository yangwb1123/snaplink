package ginadapter

import (
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/adapters/routertest"
	"github.com/yangwb1123/snaplink/shared/core"
)

// TestGinRouter_Conformance hooks the gin adapter into the shared router
// conformance suite. The Factory uses the public constructor with default
// wiring (no options), exactly what sso.WithRouter embeddings get; the
// suite's byte-identity scenarios are the regression tripwire for the
// constructor-installed 404 normalization and the RegisterGated gate.
func TestGinRouter_Conformance(t *testing.T) {
	routertest.ConformanceSuite{Factory: func(t *testing.T) core.Router {
		return NewGinRouter()
	}}.Run(t)
}
