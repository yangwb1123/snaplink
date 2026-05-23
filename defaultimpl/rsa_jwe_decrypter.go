package defaultimpl

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/go-jose/go-jose/v4"

	"github.com/snaplink/sso"
)

// RSAJWEDecrypter unwraps RFC 9101 JAR request objects encrypted to
// the AS's RSA public key. The default cipher suite — RSA-OAEP-256
// for key wrapping + A256GCM for content encryption — matches the
// FAPI 2.0 recommendation and is what every off-the-shelf JOSE
// client emits by default.
//
// The decrypter implements [security.JWEDecrypter] for the JAR pipeline
// AND [sso.JWKSProvider] so the matching public key surfaces at
// /.well-known/jwks.json with `use: "enc"` — RPs introspect that
// to know which kid to encrypt to. Symmetric companion: the existing
// Ed25519 signing keys (use: "sig") continue to be advertised by
// the Ed25519JWTIssuer, so a single JWKS document carries both
// roles.
type RSAJWEDecrypter struct {
	priv *rsa.PrivateKey
	kid  string

	// Cached at construction so JWKS() doesn't recompute on every poll.
	pubJWK sso.JWK
}

// NewRSAJWEDecrypter wraps the supplied RSA private key. kid identifies
// the key in JWKS responses — RPs sign their encrypted request objects
// referencing this kid in the JWE protected header. Empty kid is
// accepted (the JWKS entry omits the field; RPs encrypt to "the
// first / only encryption key" by `use: enc`), but production
// deployments should set a stable kid so rotation works.
func NewRSAJWEDecrypter(priv *rsa.PrivateKey, kid string) (*RSAJWEDecrypter, error) {
	if priv == nil {
		return nil, errors.New("rsa_jwe: nil private key")
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("rsa_jwe: invalid key: %w", err)
	}
	pub := &priv.PublicKey
	jwk := sso.JWK{
		Kty: "RSA",
		Use: "enc",
		Alg: "RSA-OAEP-256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytesPaddedRight(big.NewInt(int64(pub.E)))),
	}
	return &RSAJWEDecrypter{priv: priv, kid: kid, pubJWK: jwk}, nil
}

// Decrypt parses the JWE compact serialization and returns the
// decrypted plaintext (which is expected to be a signed JAR JWT).
//
// Supported envelope:
//   - alg: RSA-OAEP-256
//   - enc: A256GCM
//
// Other algorithms are rejected at parse time so the AS doesn't
// silently accept weaker cipher suites a client might pick. Operators
// wanting additional pairs implement their own [security.JWEDecrypter]
// and wire it via [sso.WithJARDecrypter].
func (d *RSAJWEDecrypter) Decrypt(_ context.Context, jweCompact string) ([]byte, error) {
	obj, err := jose.ParseEncryptedCompact(
		jweCompact,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	if err != nil {
		return nil, fmt.Errorf("rsa_jwe: parse: %w", err)
	}
	plain, err := obj.Decrypt(d.priv)
	if err != nil {
		return nil, fmt.Errorf("rsa_jwe: decrypt: %w", err)
	}
	return plain, nil
}

// SupportedAlgs returns the JWE `alg` values this decrypter accepts.
// Single-value today — additional algorithms require a new decrypter
// (or a composed multi-key one).
func (d *RSAJWEDecrypter) SupportedAlgs() []string {
	return []string{"RSA-OAEP-256"}
}

// SupportedEncs returns the JWE `enc` values this decrypter accepts.
func (d *RSAJWEDecrypter) SupportedEncs() []string {
	return []string{"A256GCM"}
}

// JWKS satisfies [sso.JWKSProvider] so the public encryption key
// surfaces at /.well-known/jwks.json alongside the issuer's signing
// keys. The two are distinguished by the `use` field — "sig" for
// signing keys, "enc" for the encryption key advertised here.
func (d *RSAJWEDecrypter) JWKS(_ context.Context) ([]sso.JWK, error) {
	return []sso.JWK{d.pubJWK}, nil
}

// bigIntToBytesPaddedRight emits the minimal big-endian encoding of n
// (no leading zeros). RFC 7518 §6.3 — the `e` JWK field is encoded
// without padding; standard `big.Int.Bytes()` already does this.
func bigIntToBytesPaddedRight(n *big.Int) []byte {
	return n.Bytes()
}
