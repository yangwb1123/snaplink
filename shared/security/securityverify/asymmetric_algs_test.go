package securityverify

import (
	"reflect"
	"testing"
)

// The shared allowlist MUST be exactly the asymmetric set the RP-facing
// client-authentication + request-integrity paths accept, and MUST contain no
// `none`/symmetric alg — the latter would let VerifyCompactJWS open the
// public-key-as-HMAC confusion attack (VerifyCompactJWS refuses such a set,
// but this guards the source).
func TestAsymmetricJWSAlgs_ExactSet(t *testing.T) {
	got := AsymmetricJWSAlgs()
	want := map[string]struct{}{
		"EdDSA": {},
		"ES256": {}, "ES384": {}, "ES512": {},
		"RS256": {},
		"PS256": {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AsymmetricJWSAlgs() = %v, want %v", got, want)
	}
	for alg := range got {
		if !isAsymmetricJWSAlg(alg) {
			t.Errorf("allowlist contains non-asymmetric alg %q", alg)
		}
	}
	if _, ok := got["none"]; ok {
		t.Error("allowlist must not contain none")
	}
	for _, hs := range []string{"HS256", "HS384", "HS512"} {
		if _, ok := got[hs]; ok {
			t.Errorf("allowlist must not contain symmetric %q", hs)
		}
	}
}

// A fresh map per call so one path cannot mutate another path's allowlist.
func TestAsymmetricJWSAlgs_FreshCopy(t *testing.T) {
	a := AsymmetricJWSAlgs()
	a["INJECTED"] = struct{}{}
	b := AsymmetricJWSAlgs()
	if _, ok := b["INJECTED"]; ok {
		t.Fatal("AsymmetricJWSAlgs() returned a shared map; a caller mutated the source")
	}
}

func TestAsymmetricJWSAlgValues_SortedAndComplete(t *testing.T) {
	got := AsymmetricJWSAlgValues()
	// sort.Strings is byte-ordered: 'S' (0x53) < 'd' (0x64), so "ES*"
	// precedes "EdDSA".
	want := []string{"ES256", "ES384", "ES512", "EdDSA", "PS256", "RS256"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AsymmetricJWSAlgValues() = %v, want %v (sorted)", got, want)
	}
}
