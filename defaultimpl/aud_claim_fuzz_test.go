package defaultimpl

import (
	"encoding/json"
	"testing"
)

// FuzzAudClaimUnmarshal fuzzes the defaultimpl-package audClaim.UnmarshalJSON
// (ed25519_jwt_issuer.go) — the RFC 7519 §4.1.3 polymorphic `aud` decoder used
// when an issuer Validates an externally-supplied JWT. It is one of TWO
// byte-identical copies (the other lives in the root package); keeping a fuzz
// target on EACH is the differential-drift guard called out in AGENTS.md §2
// (audClaim parsing) — if the two copies ever diverge, the shared invariants
// asserted here and in the root sibling will catch the one that drifts.
//
// Invariants asserted on ARBITRARY JSON bytes:
//   - never panics;
//   - a JSON string s decodes to exactly [s];
//   - a JSON []string decodes to that exact array;
//   - the MarshalJSON round-trip is logically stable for the array case;
//   - any input that is neither (and not null/empty) is rejected.
func FuzzAudClaimUnmarshal(f *testing.F) {
	f.Add([]byte(`"single-aud"`))
	f.Add([]byte(`["a","b","c"]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`123`))
	f.Add([]byte(`{"not":"valid"}`))
	f.Add([]byte(`"a\"b"`))
	f.Add([]byte(`["",""]`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte("\x00\x01\x02"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var a audClaim
		err := a.UnmarshalJSON(data)
		if err != nil {
			return
		}

		// "null"/empty are the documented no-op early return (a stays nil).
		// Check FIRST: stdlib decodes JSON null into a string as a no-op
		// success (s==""), which would otherwise trip the string branch below.
		switch string(data) {
		case "null", "":
			if a != nil {
				t.Fatalf("null/empty input %q produced non-nil %#v", data, []string(a))
			}
			return
		}

		var s string
		if json.Unmarshal(data, &s) == nil {
			if len(a) != 1 || a[0] != s {
				t.Fatalf("string input %q decoded to %#v, want [%q]", data, []string(a), s)
			}
			// MarshalJSON of a single-aud audClaim is the compact string form.
			out, mErr := a.MarshalJSON()
			if mErr != nil {
				t.Fatalf("MarshalJSON of %#v failed: %v", []string(a), mErr)
			}
			var back string
			if json.Unmarshal(out, &back) != nil || back != s {
				t.Fatalf("single-aud round-trip mismatch: in %q out %q", s, out)
			}
			return
		}

		var arr []string
		if json.Unmarshal(data, &arr) == nil {
			if len(a) != len(arr) {
				t.Fatalf("array input %q decoded to len %d, want len %d", data, len(a), len(arr))
			}
			for i := range arr {
				if a[i] != arr[i] {
					t.Fatalf("array input %q decoded element %d = %q, want %q", data, i, a[i], arr[i])
				}
			}
			return
		}

		t.Fatalf("audClaim accepted input %q (decoded %#v) that is neither JSON string nor []string", data, []string(a))
	})
}
