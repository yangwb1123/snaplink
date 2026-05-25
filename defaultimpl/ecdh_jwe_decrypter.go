package defaultimpl

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"github.com/snaplink/sso"
)

// ECDHJWEDecrypter unwraps RFC 9101 JAR request objects encrypted to the
// AS's EC public key using ECDH-ES (or ECDH-ES+A256KW) key agreement +
// A256GCM content encryption. It is the EC counterpart to
// [RSAJWEDecrypter], for RPs that prefer EC over RSA (the natural pairing
// with ES256 signing).
//
// Implements [security.JWEDecrypter] for the JAR pipeline AND
// [sso.JWKSProvider] so the matching public key surfaces at
// /.well-known/jwks.json with use:"enc" — RPs introspect it to know
// which kid to encrypt to. Signing keys (use:"sig") published by the
// signing issuer coexist in the same document.
type ECDHJWEDecrypter struct {
	priv   *ecdsa.PrivateKey
	kid    string
	pubJWK sso.JWK
}

// NewECDHJWEDecrypter wraps the supplied EC private key (P-256/384/521).
// kid identifies the key in JWKS; RPs reference it in the JWE protected
// header. Empty kid is accepted but production deployments should set a
// stable one so rotation works.
func NewECDHJWEDecrypter(priv *ecdsa.PrivateKey, kid string) (*ECDHJWEDecrypter, error) {
	if priv == nil {
		return nil, errors.New("ecdh_jwe: nil private key")
	}
	crv := priv.Curve.Params().Name
	switch crv {
	case "P-256", "P-384", "P-521":
	default:
		return nil, fmt.Errorf("ecdh_jwe: unsupported curve %q", crv)
	}
	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	xb := make([]byte, byteLen)
	yb := make([]byte, byteLen)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	jwk := sso.JWK{
		Kty: "EC",
		Use: "enc",
		Kid: kid,
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(xb),
		Y:   base64.RawURLEncoding.EncodeToString(yb),
	}
	return &ECDHJWEDecrypter{priv: priv, kid: kid, pubJWK: jwk}, nil
}

var _ sso.JWKSProvider = (*ECDHJWEDecrypter)(nil)

// Decrypt parses the JWE compact serialization and returns the decrypted
// plaintext (a signed JAR JWT). Only ECDH-ES / ECDH-ES+A256KW + A256GCM
// are accepted; other suites are rejected at parse time so the AS never
// silently accepts a weaker envelope.
func (d *ECDHJWEDecrypter) Decrypt(_ context.Context, jweCompact string) ([]byte, error) {
	obj, err := jose.ParseEncryptedCompact(
		jweCompact,
		[]jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	if err != nil {
		return nil, fmt.Errorf("ecdh_jwe: parse: %w", err)
	}
	plain, err := obj.Decrypt(d.priv)
	if err != nil {
		return nil, fmt.Errorf("ecdh_jwe: decrypt: %w", err)
	}
	return plain, nil
}

// SupportedAlgs returns the JWE `alg` values this decrypter accepts.
func (d *ECDHJWEDecrypter) SupportedAlgs() []string {
	return []string{algECDHES, algECDHESA256KW}
}

// SupportedEncs returns the JWE `enc` values this decrypter accepts.
func (d *ECDHJWEDecrypter) SupportedEncs() []string {
	return []string{"A256GCM"}
}

// JWKS satisfies [sso.JWKSProvider] so the public encryption key surfaces
// at /.well-known/jwks.json (use:"enc") alongside the issuer's signing
// keys.
func (d *ECDHJWEDecrypter) JWKS(_ context.Context) ([]sso.JWK, error) {
	return []sso.JWK{d.pubJWK}, nil
}
