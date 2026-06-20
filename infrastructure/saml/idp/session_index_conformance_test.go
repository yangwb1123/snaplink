package idp_test

import (
	"testing"

	samlidp "github.com/snaplink/sso/saml/idp"
	"github.com/snaplink/sso/saml/samltest/sessionindextest"
)

// spsPerSubjectCapForTest is a small per-subject SP cap so the cap conformance
// subtest drives past it cheaply (the production default is 64).
const spsPerSubjectCapForTest = 8

// TestSessionIndexConformance_Memory runs the shared session-index conformance
// suite against the in-memory MemorySessionIndex. The sqlite peer runs the SAME
// suite in saml/idp/sqlite. The suite skips the (memory-only) subject-LRU bound
// by design (see SessionIndexConformance's doc) and exercises the per-subject SP
// cap both backends keep.
//
// EXTERNAL `package idp_test` (not internal `package idp`): the suite imports
// idp, so an internal test importing it would cycle; an external test may import
// the package it tests. MemorySessionIndex's constructor is exported, so no
// internal access is needed.
func TestSessionIndexConformance_Memory(t *testing.T) {
	sessionindextest.SessionIndexConformance{
		Factory: func(t *testing.T) samlidp.SAMLSessionIndex {
			return samlidp.NewMemorySessionIndex(0, spsPerSubjectCapForTest)
		},
		SPsPerSubjectCap: spsPerSubjectCapForTest,
	}.Run(t)
}
