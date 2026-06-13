package security

import (
	"slices"
	"strings"
	"testing"
)

// These two predicates gate the JAR `request_uri` SSRF surface: they decide
// whether an attacker-supplied URL is routed to the URL-fetch path at all
// (IsJARFetchableURI) and whether it survives the per-client allowlist
// (IsRequestURIAllowed). Both run on fully attacker-controlled strings on the
// /auth/login redirect-time path, so a panic on a hostile URI (embedded NULs,
// non-utf8, gigabyte hosts, percent-encoding tricks) is a remote DoS. The
// invariants below are the load-bearing security contract — a regression that
// lets a non-https scheme through, or that returns true against an empty
// allowlist, re-opens the SSRF pivot the allowlist exists to close.

// FuzzIsJARFetchableURI throws arbitrary URI strings at the real routing
// predicate and asserts: it never panics, and it returns true ONLY for inputs
// that genuinely begin with the literal `https://` scheme prefix. The
// independent prefix check below is intentionally NOT a url.Parse — the
// production contract is a byte-prefix gate (uppercase HTTPS://, leading
// whitespace, file://, http://, javascript: all must route to false), and the
// oracle must mirror that exact contract, not a normalized-scheme notion of it.
func FuzzIsJARFetchableURI(f *testing.F) {
	f.Add("https://a.example/x")                      // canonical fetchable
	f.Add("http://a")                                 // plain HTTP — must be rejected
	f.Add("https://[::1]/")                           // IPv6 loopback literal
	f.Add("https://a#frag")                           // fragment present — prefix still holds
	f.Add("https://a?x=%2e%2e%2f")                    // percent-encoded ../ in query
	f.Add("javascript:alert(1)")                      // pseudo-scheme
	f.Add("file:///etc/passwd")                       // local file scheme
	f.Add("ftp://host/x")                             // other scheme
	f.Add("HTTPS://A")                                // uppercase — prefix gate is case-sensitive
	f.Add(" https://a")                               // leading space defeats the prefix
	f.Add("https:/a")                                 // single-slash near-miss
	f.Add("https://")                                 // scheme prefix with empty authority
	f.Add("urn:ietf:params:oauth:request_uri:abc")    // PAR urn path, not JAR
	f.Add("")                                         // empty
	f.Add("https://" + strings.Repeat("a", 100000))   // huge host segment
	f.Add("https://a\x00.example/x")                  // embedded NUL
	f.Add("https://a\n.example/x")                    // embedded newline (header-split shape)
	f.Add("https://\xff\xfe/x")                       // non-utf8 bytes in authority
	f.Add("https://a/" + strings.Repeat("../", 5000)) // deeply nested traversal

	f.Fuzz(func(t *testing.T, uri string) {
		got := IsJARFetchableURI(uri)

		// Independent restatement of the documented contract: fetchable iff the
		// raw string starts with the exact https:// prefix. Computed without
		// reusing the function under test so a regression in the predicate
		// cannot also silently corrupt the oracle.
		want := strings.HasPrefix(uri, "https://")
		if got != want {
			t.Fatalf("IsJARFetchableURI(%q) = %v, want %v (https-prefix contract)", uri, got, want)
		}

		// Hard security floor independent of the prefix arithmetic: anything the
		// predicate green-lights for fetching MUST be https. If this ever fires,
		// a non-https URI reached the SSRF-relevant fetch path.
		if got && !strings.HasPrefix(uri, "https://") {
			t.Fatalf("IsJARFetchableURI(%q) accepted a non-https URI", uri)
		}
	})
}

// FuzzIsRequestURIAllowed drives the per-client allowlist check with a fuzzed
// URI and a small fuzzed candidate list and asserts: it never panics; an empty
// allowlist NEVER returns true (the no-SSRF-surface default); and a true result
// ALWAYS implies the URI is byte-for-byte present in the allowlist (no wildcard
// / prefix / normalization slack that an attacker could exploit to smuggle an
// internal host past an exact-match registration).
func FuzzIsRequestURIAllowed(f *testing.F) {
	// listSelector deterministically derives the allowlist from the fuzzed
	// inputs so the fuzzer explores empty / disjoint / containing / duplicate
	// / near-miss lists rather than a single fixed shape.
	f.Add("https://a.example/x", "https://a.example/x", uint8(0))
	f.Add("https://a.example/x", "https://b.example/y", uint8(1))
	f.Add("https://a.example/x", "", uint8(2))
	f.Add("", "", uint8(0))
	f.Add("https://a.example/x", "https://a.example/x\x00", uint8(3)) // NUL near-miss
	f.Add("https://a#frag", "https://a", uint8(1))
	f.Add("https://A.EXAMPLE/X", "https://a.example/x", uint8(0))           // case mismatch
	f.Add(strings.Repeat("a", 70000), strings.Repeat("a", 70000), uint8(0)) // huge equal entries
	f.Add("https://a\n/x", "https://a\n/x", uint8(0))                       // embedded newline match
	f.Add("\xff\xfe", "\xff\xfe", uint8(0))                                 // non-utf8 match
	f.Add("javascript:x", "javascript:x", uint8(4))

	f.Fuzz(func(t *testing.T, uri, other string, listSelector uint8) {
		var allowed []string
		switch listSelector % 6 {
		case 0:
			// Empty allowlist — the deny-by-default contract.
			allowed = nil
		case 1:
			// Disjoint single entry.
			allowed = []string{other}
		case 2:
			// Contains the exact URI plus noise.
			allowed = []string{"https://noise.example/z", uri, other}
		case 3:
			// Duplicated entries around the URI.
			allowed = []string{uri, uri, other}
		case 4:
			// Only near-misses (uri with suffixes) — must NOT match unless equal.
			allowed = []string{uri + "/", "x" + uri, other}
		default:
			// Both fuzzed strings, neither guaranteed to equal uri.
			allowed = []string{other, "https://other.example/q"}
		}

		got := IsRequestURIAllowed(uri, allowed)

		// Deny-by-default: an empty allowlist exposes no fetch surface, ever.
		if len(allowed) == 0 && got {
			t.Fatalf("IsRequestURIAllowed(%q, empty) returned true", uri)
		}

		// Exact-match contract: a positive result must be backed by a literal
		// member equal to uri. slices.Contains is the independent witness; if
		// the predicate ever returned true without a byte-equal entry, a
		// wildcard/normalization bug would have crept in.
		if got && !slices.Contains(allowed, uri) {
			t.Fatalf("IsRequestURIAllowed(%q, %q) returned true without an exact match", uri, allowed)
		}
		// And the converse: an exact member present must be allowed (no
		// spurious rejection that would break legitimate registrations).
		if !got && slices.Contains(allowed, uri) {
			t.Fatalf("IsRequestURIAllowed(%q, %q) returned false despite an exact match", uri, allowed)
		}
	})
}
