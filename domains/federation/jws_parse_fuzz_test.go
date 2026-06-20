package federation

import (
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzParseStatement throws arbitrary strings at the federation trust-chain
// statement parsers (parseStatement and the splitCompactJWS / unverifiedPayload
// / jwsHeaderTyp / requireEntityStatementTyp primitives it is built on) and
// asserts they survive ANY input.
//
// These decode an ATTACKER-CONTROLLED compact JWS: a hostile leaf self-reports
// its authority_hints / jwks / fetch endpoint, and the resolver MUST read those
// fields UNVERIFIED to navigate the walk before any signature check. The bytes
// arrive over the network (entity-config fetch, §8 /fetch, subordinate
// statements), so malformed base64, oversized or empty segments, non-JSON
// payloads, wrong segment counts, and non-UTF8 garbage must all be rejected
// gracefully. A panic here is a pre-auth remote DoS on the federation surface.
//
// Invariants asserted (values are attacker-supplied, so only STRUCTURAL
// guarantees are checked, never claim contents):
//
//   - none of the five parsers ever panics;
//   - on nil error parseStatement returns a chainLink whose .compact is the
//     verbatim input (the impl stamps compact: compact — a regression that
//     dropped or rewrote it would silently desync the walk's later signature
//     verification, which re-reads .compact);
//   - parseStatement and unverifiedPayload agree: parseStatement decodes the
//     SAME payload unverifiedPayload does (it is built on it), so a nil error
//     from one MUST coincide with a nil error from the other for the split;
//   - requireEntityStatementTyp == nil IMPLIES jwsHeaderTyp == EntityStatementTyp
//     (the typ gate must never pass a token whose header typ it could not read
//     or that carries the wrong typ — that gate is what stops a plain id/access
//     token signed by the same key from masquerading as a federation statement).
func FuzzParseStatement(f *testing.F) {
	enc := base64.RawURLEncoding.EncodeToString

	// Valid 3-segment JWS-shaped statement: entity-statement+jwt header +
	// well-formed EntityStatementClaims payload + a (never-verified) signature.
	validHeader := enc([]byte(`{"alg":"EdDSA","typ":"entity-statement+jwt","kid":"k1"}`))
	validClaims := enc([]byte(`{"iss":"https://leaf.example","sub":"https://leaf.example","iat":1,"exp":9999999999,"authority_hints":["https://anchor.example"],"jwks":{"keys":[]}}`))
	f.Add(validHeader + "." + validClaims + ".c2ln")

	// Same shape but the header typ is a plain access token: the typ gate must
	// reject it even though the statement payload parses fine.
	wrongTyp := enc([]byte(`{"alg":"EdDSA","typ":"at+jwt"}`))
	f.Add(wrongTyp + "." + validClaims + ".c2ln")

	// Wrong segment counts.
	f.Add(validHeader + "." + validClaims) // 2-segment
	f.Add(validHeader + "." + validClaims + ".c2ln.extra.more")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("a.b.") // empty (and thus rejected) trailing signature segment
	f.Add(".b.c") // empty header segment
	f.Add("a..c") // empty payload segment

	// Segment that is not valid base64url.
	f.Add("!!!." + validClaims + ".sig")
	f.Add(validHeader + ".@@@@.sig")
	f.Add("###.$$$.%%%")

	// Payload that base64url-decodes cleanly but is NOT JSON.
	f.Add(validHeader + "." + enc([]byte("this is plainly not json {{{")) + ".sig")
	// Payload that is valid JSON but the WRONG type (array, not object).
	f.Add(validHeader + "." + enc([]byte(`[1,2,3]`)) + ".sig")
	// Payload that is the JSON literal null.
	f.Add(validHeader + "." + enc([]byte(`null`)) + ".sig")

	// Deeply nested JSON in metadata_policy / authority_hints to stress the
	// decoder against stack-style blowups on attacker-chosen nesting.
	f.Add(validHeader + "." + enc([]byte(`{"iss":"a","sub":"a","exp":1,"authority_hints":[[[[[[[[[[]]]]]]]]]]}`)) + ".sig")
	f.Add(validHeader + "." + enc([]byte(`{"metadata_policy":`+strings.Repeat(`{"x":`, 64)+`{}`+strings.Repeat(`}`, 64)+`}`)) + ".sig")

	// Huge single segment (oversized base64 input) and non-UTF8 bytes embedded.
	f.Add(strings.Repeat("A", 65536) + "." + validClaims + ".sig")
	f.Add(validHeader + "." + enc([]byte("\x00\x01\xff\xfe\xc3\x28")) + ".sig")
	// Many dots: must collapse to the not-3-segment error, never index OOB.
	f.Add(strings.Repeat(".", 4096))

	f.Fuzz(func(t *testing.T, compact string) {
		// 1. splitCompactJWS: the lowest-level primitive every other parser is
		// built on. Must never panic; on success the three returned segments
		// must reconstruct the input exactly (header.payload.sig), proving the
		// indices it computed are in-bounds and consistent.
		h, p, s, splitErr := splitCompactJWS(compact)
		if splitErr == nil {
			if got := h + "." + p + "." + s; got != compact {
				t.Fatalf("splitCompactJWS round-trip mismatch: in=%q reassembled=%q", compact, got)
			}
		}

		// 2. unverifiedPayload: must agree with splitCompactJWS on the split. A
		// payload-decode error is allowed even when the split succeeded (bad
		// base64), but a split error MUST propagate (no payload without a split).
		payload, payloadErr := unverifiedPayload(compact)
		if payloadErr != nil && payload != nil {
			t.Fatalf("unverifiedPayload returned non-nil payload (%q) alongside error %v", payload, payloadErr)
		}
		if splitErr != nil && payloadErr == nil {
			t.Fatalf("unverifiedPayload succeeded where splitCompactJWS failed: %q", compact)
		}

		// 3. jwsHeaderTyp: never panics; success requires a clean split.
		typ, typErr := jwsHeaderTyp(compact)
		if splitErr != nil && typErr == nil {
			t.Fatalf("jwsHeaderTyp succeeded where splitCompactJWS failed: %q", compact)
		}

		// 4. requireEntityStatementTyp: the BEFORE-signature typ gate. A nil
		// error here is the load-bearing security claim — it must coincide with
		// a readable header typ that is EXACTLY the federation statement typ.
		// Anything else (unreadable header, wrong typ) must be an error, or a
		// wrong-shaped token signed by the right key could pass as a statement.
		if reqErr := requireEntityStatementTyp(compact); reqErr == nil {
			if typErr != nil {
				t.Fatalf("requireEntityStatementTyp passed but jwsHeaderTyp errored (%v): %q", typErr, compact)
			}
			if typ != EntityStatementTyp {
				t.Fatalf("requireEntityStatementTyp passed with typ %q != %q: %q", typ, EntityStatementTyp, compact)
			}
		}

		// 5. parseStatement: the real target. Must never panic. On nil error the
		// returned link must carry the verbatim input as .compact (the walk
		// later re-verifies that exact string's signature, so a desync here is a
		// correctness/security regression), and the payload split it relied on
		// must itself have succeeded.
		link, parseErr := parseStatement(compact)
		if parseErr == nil {
			if link.compact != compact {
				t.Fatalf("parseStatement nil-err but link.compact %q != input %q", link.compact, compact)
			}
			if payloadErr != nil {
				t.Fatalf("parseStatement succeeded but unverifiedPayload errored (%v): %q", payloadErr, compact)
			}
		}
	})
}
