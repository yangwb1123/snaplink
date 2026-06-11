package defaultimpl

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

// accessTokenHash computes the OpenID Connect Core 1.0 §3.1.3.6 `at_hash`:
// the base64url encoding of the left-most half of the hash of the ASCII
// octets of the access_token value. The hash function is the one the
// id_token's JWS signing alg uses — so an RP recomputes it from the
// `alg` header. The "half" is the left N/2 bytes of the digest, i.e.
// SHA-256 yields 128 bits and SHA-512 yields 256 bits.
//
// jwsAlg is the issuer's signing alg constant. The three default issuers
// only ever publish EdDSA (Ed25519), ES256, RS256, or PS256 — the latter
// three all hash with SHA-256, EdDSA(Ed25519) with SHA-512. EdDSA has no
// at_hash mapping in OIDC Core (which predates it); SHA-512 is the
// convention the ecosystem settled on (panva/jose, node-oidc-provider),
// being Ed25519's own internal hash — using anything else makes every
// RP's at_hash check fail. A future issuer whose alg hashes with neither
// SHA-256 nor SHA-512 (e.g. ES384/ES512) MUST add a case here.
//
// An empty access_token returns "" so the caller's `omitempty` drops the
// claim — at_hash is REQUIRED only when an access_token is returned in
// the same response as the id_token, so callers pass it exactly then.
func accessTokenHash(jwsAlg, accessToken string) string {
	if accessToken == "" {
		return ""
	}
	var digest []byte
	switch jwsAlg {
	case jwtAlgEdDSA:
		sum := sha512.Sum512([]byte(accessToken))
		digest = sum[:]
	default: // ES256 / RS256 / PS256 — every alg these issuers publish hashes with SHA-256
		sum := sha256.Sum256([]byte(accessToken))
		digest = sum[:]
	}
	return base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
}
