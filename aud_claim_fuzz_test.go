package sso

import (
	"encoding/json"
	"testing"
)

// FuzzAudClaimUnmarshal fuzzes the root-package audClaim.UnmarshalJSON
// (server_extensions.go) — the RFC 7519 §4.1.3 polymorphic `aud` decoder used
// when parsing untrusted JAR / JWT control claims. It is one of TWO
// byte-identical copies (the other lives in defaultimpl); the sibling fuzz
// target FuzzAudClaimUnmarshal in package defaultimpl exercises the second.
//
// Invariants asserted on ARBITRARY JSON bytes:
//   - never panics;
//   - on a successful decode of a JSON string s, the result is exactly [s];
//   - on a successful decode of a JSON array of strings, the result equals
//     that array (the canonical-shape property the verifier relies on);
//   - any input that stdlib json rejects as both a string and a []string is
//     itself rejected (no silently-empty accept of garbage).
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

		// Reference: what does the input look like to the stdlib?
		var s string
		if json.Unmarshal(data, &s) == nil {
			// A JSON string MUST decode to exactly [s].
			if len(a) != 1 || a[0] != s {
				t.Fatalf("string input %q decoded to %#v, want [%q]", data, []string(a), s)
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

		// Anything the impl accepted that stdlib rejects as both a string and
		// a []string (and which isn't null/empty, handled above) is a
		// correctness regression.
		t.Fatalf("audClaim accepted input %q (decoded %#v) that is neither JSON string nor []string", data, []string(a))
	})
}
