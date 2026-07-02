package security

import (
	"context"
	"errors"
	"github.com/snaplink/sso/shared/core"
	"strings"
)

// JWEDecrypter unwraps the encrypted variant of an RFC 9101 JAR
// `request` (or `request_uri`-fetched) payload. The client encrypts
// the request object to the AS's public encryption key so the
// authorization parameters never appear as plaintext in browser
// histories / proxy logs — the AS decrypts and then validates the
// inner signed JWS exactly like the unencrypted JAR path.
//
// Implementations advertise their algorithms via SupportedAlgs +
// SupportedEncs so [oidc_discovery.go] can populate
// `request_object_encryption_alg_values_supported` and the matching
// `enc` list. JWKSProvider is co-implemented so the public encryption
// key surfaces at `/.well-known/jwks.json` with `use: "enc"` — RPs
// pick which key to encrypt to via the `kid`.
//
// Wire via [WithJARDecrypter]. Without it, JWE-shaped JAR payloads
// at /auth/login surface as invalid_request_object (the AS can't
// decrypt, so it can't validate; failing closed is the only safe
// move).
type JWEDecrypter interface {
	// Decrypt parses the JWE compact serialization (5 dot-separated
	// base64url segments) and returns the plaintext bytes. The
	// plaintext is expected to itself be a JWS (the signed JAR JWT),
	// which the standard verifyJAR pipeline validates afterwards.
	//
	// Returns ErrJWENotEncrypted when the input doesn't have the JWE
	// shape (3 segments → already a JWS, pass through). All other
	// errors are collapsed to invalid_request_object on the wire.
	Decrypt(ctx context.Context, jwe string) ([]byte, error)

	// SupportedAlgs lists the JWE `alg` (key-management) values this
	// decrypter accepts. Examples: "RSA-OAEP-256", "ECDH-ES",
	// "ECDH-ES+A256KW".
	SupportedAlgs() []string

	// SupportedEncs lists the JWE `enc` (content-encryption) values
	// this decrypter accepts. Examples: "A256GCM", "A128CBC-HS256".
	SupportedEncs() []string
}

// ErrJWENotEncrypted signals that the supplied payload isn't JWE-shaped
// (3 segments = JWS; 5 segments = JWE). Callers use this to fall through
// to the plain-JWS verification path without treating the mismatch as
// an error.
var ErrJWENotEncrypted = errors.New("jwe: payload is not JWE-encrypted (wrong segment count)")

// isJWECompact reports whether the supplied string has the
// 5-segment JWE compact serialization shape. Cheap shape-check used
// to decide between the plain-JWS and JWE-then-JWS verification paths
// without parsing — actual structure validation happens during
// JWEDecrypter.Decrypt.
func isJWECompact(s string) bool {
	if s == "" {
		return false
	}
	return strings.Count(s, ".") == 4
}

// JWEUnwrap is the integration point verifyJAR calls. If the payload
// looks like JWE AND a decrypter is wired, decrypt; otherwise pass
// through unchanged.
func JWEUnwrap(ctx context.Context, raw string, dec JWEDecrypter) (string, error) {
	if !isJWECompact(raw) {
		return raw, nil
	}
	if dec == nil {
		// JWE arrived but no decrypter wired — fail closed. The caller
		// (handler.go) maps the error to invalid_request_object so the
		// RP can fall back to plaintext / signed JAR.
		return "", errors.New("jwe: encrypted request object received but no JWEDecrypter wired")
	}
	plain, err := dec.Decrypt(ctx, raw)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// JWEEncrypter wraps a server-produced response artifact (a signed ID
// Token JWS, or a signed/JSON /userinfo payload) in a JWE addressed to
// the relying party's public encryption key. It is the response-
// direction mirror of [JWEDecrypter] (which unwraps RFC 9101 encrypted
// JAR request objects the RP sends TO the AS): here the AS encrypts a
// response TO the RP so the ID Token / userinfo claims never traverse
// the user agent or intermediaries in the clear.
//
// recipientJWKS is the client's registered JWKS (Client.JWKS). The
// encrypter selects the entry whose `use` is "enc" (or unset) and whose
// key type matches the requested alg, encrypts to it, and returns the
// JWE compact serialization (5 dot-separated base64url segments). The
// RP decrypts with the matching private key.
//
// Wire via [WithJWEResponseEncrypter]. Without it, clients that
// registered an `*_encrypted_response_alg` get the artifact omitted
// (ID Token) / a server_error (userinfo) rather than a plaintext
// response — fail-closed, never downgrade to cleartext.
type JWEEncrypter interface {
	// Encrypt wraps plaintext in a JWE for the recipient identified in
	// recipientJWKS, using the named JWE key-management (alg) +
	// content-encryption (enc) algorithms. Returns the JWE compact
	// serialization.
	//
	// Errors (no usable recipient key, unsupported alg/enc, crypto
	// failure) MUST be returned undifferentiated by the caller on the
	// wire — the caller collapses them to a single response so the RP
	// can't distinguish "no key" from "crypto failed" (oracle-leak
	// hardening, AGENTS.md §2).
	Encrypt(ctx context.Context, plaintext []byte, recipientJWKS []core.JWK, alg, enc string) (string, error)

	// SupportedAlgs lists the JWE `alg` (key-management) values this
	// encrypter can produce. Surfaced in discovery's
	// id_token_encryption_alg_values_supported +
	// userinfo_encryption_alg_values_supported.
	SupportedAlgs() []string

	// SupportedEncs lists the JWE `enc` (content-encryption) values
	// this encrypter can produce.
	SupportedEncs() []string
}
