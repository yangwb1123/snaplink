package security

import (
	"context"

	"github.com/snaplink/sso/core"
)

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
