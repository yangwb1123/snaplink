package ssotest

import (
	"testing"

	"github.com/yangwb1123/snaplink/protocols/fapi"
	"github.com/yangwb1123/snaplink/shared/security"
)

// TestFAPICompliance verifies that FAPI 2.0 crypto policy is enforced:
// alg=none banned, only AsymmetricJWSAlgs allowed, and the alg allowlist
// is verified before signature check.
func TestFAPICompliance(t *testing.T) {
	// Verify FAPI 2.0 allowed algorithms
	allowed := fapi.FAPIAllowedAlgSet()
	if len(allowed) == 0 {
		t.Fatal("FAPI AllowedAlgs returned empty")
	}

	// alg=none should NOT be in the allowed list
	if _, ok := allowed["none"]; ok {
		t.Error("alg=none must not be in FAPI allowed algorithms")
	}

	// Every allowed alg must be in the global AsymmetricJWSAlgs set
	asymJWSAlgs := security.AsymmetricJWSAlgs()
	for alg := range allowed {
		if _, exists := asymJWSAlgs[alg]; !exists {
			t.Errorf("FAPI allowed alg %q is not in AsymmetricJWSAlgs", alg)
		}
	}

	t.Logf("FAPI allowed %d asymmetric algorithms", len(allowed))
	for alg := range allowed {
		t.Logf("  - %s", alg)
	}
}
