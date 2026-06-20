package defaultjwe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/snaplink/sso/shared/security"
)

// FuzzJWEUnwrap throws arbitrary strings at the real security.JWEUnwrap with a
// real RSAJWEDecrypter wired, exercising the full compact-JWE parse + decrypt
// path the JAR pipeline runs on attacker-supplied request objects.
//
// JWEUnwrap sits on the /auth/login (and request_uri-fetched) JAR surface:
// the value here is fully client-controlled, so a panic anywhere in the
// segment-split, base64 decode, JOSE header parse, key-unwrap, or AEAD-open
// stages is a remote DoS. The encrypted request object is decrypted BEFORE the
// inner JWS is validated, meaning malformed 5-segment envelopes, wrong-alg
// protected headers, truncated ciphertext, and non-base64 segments all reach
// this code with zero prior trust.
//
// Invariants asserted on ANY input:
//   - JWEUnwrap NEVER panics;
//   - when the input is NOT 5-segment JWE-compact shaped, it is a verbatim
//     passthrough: returns (raw, nil) unchanged (the plain-JWS / non-JWE fall
//     through that verifyJAR depends on — a mutated passthrough would smuggle a
//     different request object than the one inspected);
//   - 5-segment input that does not decrypt under the wired key returns a
//     non-nil error AND an empty plaintext (fail-closed; never a partial /
//     attacker-influenced plaintext escaping as success).
//
// The decrypter is built ONCE outside the per-input closure: RSA keygen is
// expensive and the key is immutable, so amortizing it keeps the fuzzer hot.
func FuzzJWEUnwrap(f *testing.F) {
	// 2048-bit is the smallest FAPI-acceptable RSA size and keeps keygen cheap
	// for the fuzz harness; the parse/decrypt code paths are size-independent.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("rsa keygen: %v", err)
	}
	dec, err := NewRSAJWEDecrypter(priv, "enc-1")
	if err != nil {
		f.Fatalf("NewRSAJWEDecrypter: %v", err)
	}

	// 3-segment JWS-shaped passthrough: not JWE, must return unchanged.
	f.Add("a.b.c")
	// 5-segment garbage: JWE-shaped but undecryptable → error, empty plaintext.
	f.Add("a.b.c.d.e")
	// Empty: not JWE-shaped → passthrough.
	f.Add("")
	// 5 segments of invalid base64: split succeeds, header decode must fail
	// without panicking.
	f.Add("!!!.@@@.###.$$$.%%%")
	// Protected header claiming an unsupported alg (HS256/A128CBC-HS256) the
	// strict RSA-OAEP-256 parser must reject, not crash:
	// {"alg":"HS256","enc":"A128CBC-HS256"} base64url, 4 empty trailing segs.
	f.Add("eyJhbGciOiJIUzI1NiIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ....")
	// Protected header claiming alg=none — the JWE analogue of the alg=none
	// downgrade; must fail closed.
	f.Add("eyJhbGciOiJub25lIiwiZW5jIjoiQTI1NkdDTSJ9....")
	// Oversized ciphertext segment: a huge non-base64 blob in the ciphertext
	// position to probe length-driven allocation / split handling.
	f.Add("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.AAAA.BBBB." +
		strings.Repeat("Z", 1<<16) + ".CCCC")
	// Non-utf8 / NUL bytes scattered through 5 segments.
	f.Add("\x00\xff.\x01\x02.\xfe\xfd.\xc0\xc1.\x80\x80")
	// Nested dots inside an otherwise JWE-shaped string: exactly 4 dots is the
	// shape gate; more or fewer flips passthrough vs decrypt.
	f.Add("....")
	// Six segments (5 dots): NOT JWE-compact (count!=4) → passthrough.
	f.Add("a.b.c.d.e.f")
	// Valid RSA-OAEP-256/A256GCM header, truncated/garbage CEK + ciphertext +
	// tag: reaches the key-unwrap stage and must fail closed.
	f.Add("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.QUJD.REVG.R0hJ.SktM")

	f.Fuzz(func(t *testing.T, raw string) {
		// Independent shape oracle: 5-segment compact JWE has exactly 4 dots.
		// Replicated here (security.isJWECompact is unexported) so the
		// passthrough assertion is a check, not a tautology against the impl.
		isCompact := raw != "" && strings.Count(raw, ".") == 4

		out, err := security.JWEUnwrap(context.Background(), raw, dec)

		if !isCompact {
			// Non-JWE input must pass through byte-for-byte with no error;
			// any mutation here would let a request object differ from the one
			// the AS later inspects.
			if err != nil {
				t.Fatalf("non-JWE input %q returned error %v (want passthrough)", raw, err)
			}
			if out != raw {
				t.Fatalf("non-JWE input %q mutated to %q (want verbatim passthrough)", raw, out)
			}
			return
		}

		// JWE-shaped input: with this random key it can never legitimately
		// decrypt, so the only correct outcome is fail-closed.
		if err == nil {
			t.Fatalf("JWE-shaped input %q decrypted successfully under a random key (impossible without a real envelope); out=%q", raw, out)
		}
		if out != "" {
			t.Fatalf("JWE-shaped input %q failed (%v) but returned non-empty plaintext %q (must be empty on error)", raw, err, out)
		}
	})
}
