package defaultimpl

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/go-jose/go-jose/v4"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
)

// ECDH JWE algorithm names (RFC 7518 §4.6). ECDH-ES is direct key
// agreement (one recipient); ECDH-ES+A256KW agrees a shared secret then
// AES-key-wraps the CEK (lets the AS reuse a CEK across recipients, and
// is what some RPs register).
const (
	algECDHES       = "ECDH-ES"
	algECDHESA256KW = "ECDH-ES+A256KW"
)

// ECDHJWEResponseEncrypter wraps server-produced response artifacts (ID
// Token JWS, signed/JSON userinfo) in a JWE addressed to the relying
// party's EC public encryption key, using ECDH-ES key agreement +
// A256GCM content encryption. It is the EC counterpart to
// [RSAJWEResponseEncrypter], for RPs that register EC keys (common
// alongside ES256 signing) rather than RSA.
//
// Stateless: the recipient key is selected per-call from the client's
// registered JWKS (Client.JWKS), so one encrypter serves every client.
//
// Implements [security.JWEEncrypter].
type ECDHJWEResponseEncrypter struct{}

// NewECDHJWEResponseEncrypter returns a response encrypter for the
// ECDH-ES (and ECDH-ES+A256KW) + A256GCM suite.
func NewECDHJWEResponseEncrypter() *ECDHJWEResponseEncrypter {
	return &ECDHJWEResponseEncrypter{}
}

var _ security.JWEEncrypter = (*ECDHJWEResponseEncrypter)(nil)

// errNoECEncKey signals no usable `use:enc` EC key in the recipient
// JWKS. Internal — never surfaced distinctly from a crypto failure
// (oracle-leak hardening).
var errNoECEncKey = errors.New("ecdh_jwe_enc: no usable EC encryption key in recipient JWKS")

// Encrypt wraps plaintext in a JWE for the recipient. Only ECDH-ES /
// ECDH-ES+A256KW key management with A256GCM content encryption are
// accepted; any other alg/enc is rejected so the AS never downgrades to
// a weaker suite a client might register.
func (e *ECDHJWEResponseEncrypter) Encrypt(_ context.Context, plaintext []byte, recipientJWKS []core.JWK, alg, enc string) (string, error) {
	var keyAlg jose.KeyAlgorithm
	switch alg {
	case algECDHES:
		keyAlg = jose.ECDH_ES
	case algECDHESA256KW:
		keyAlg = jose.ECDH_ES_A256KW
	default:
		return "", fmt.Errorf("ecdh_jwe_enc: unsupported alg %q", alg)
	}
	if enc != "A256GCM" {
		return "", fmt.Errorf("ecdh_jwe_enc: unsupported enc %q", enc)
	}
	pub, kid, err := selectECEncKey(recipientJWKS, alg)
	if err != nil {
		return "", err
	}

	recipient := jose.Recipient{Algorithm: keyAlg, Key: pub, KeyID: kid}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, nil)
	if err != nil {
		return "", fmt.Errorf("ecdh_jwe_enc: new encrypter: %w", err)
	}
	obj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("ecdh_jwe_enc: encrypt: %w", err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("ecdh_jwe_enc: serialize: %w", err)
	}
	return compact, nil
}

// SupportedAlgs returns the JWE `alg` values this encrypter produces.
func (e *ECDHJWEResponseEncrypter) SupportedAlgs() []string {
	return []string{algECDHES, algECDHESA256KW}
}

// SupportedEncs returns the JWE `enc` values this encrypter produces.
func (e *ECDHJWEResponseEncrypter) SupportedEncs() []string {
	return []string{"A256GCM"}
}

// selectECEncKey picks the recipient EC public key from the client JWKS,
// mirroring selectRSAEncKey's preference order: an EC key with use:"enc"
// (and matching alg when present) wins; a dual-use EC key (no `use`) is
// the fallback; signing-only keys are skipped. Returns the kid so the
// JWE header references it.
func selectECEncKey(jwks []core.JWK, alg string) (*ecdsa.PublicKey, string, error) {
	var fallback *core.JWK
	for i := range jwks {
		k := &jwks[i]
		if k.Kty != "EC" {
			continue
		}
		if k.Use == "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != alg {
			continue
		}
		if k.Use == "enc" {
			pub, err := ecPublicFromJWK(k)
			if err != nil {
				continue
			}
			return pub, k.Kid, nil
		}
		if fallback == nil {
			fallback = k
		}
	}
	if fallback != nil {
		if pub, err := ecPublicFromJWK(fallback); err == nil {
			return pub, fallback.Kid, nil
		}
	}
	return nil, "", errNoECEncKey
}

// ecPublicFromJWK reconstructs an *ecdsa.PublicKey from a JWK's crv + x +
// y parameters (RFC 7518 §6.2), validating the point lies on the curve.
func ecPublicFromJWK(k *core.JWK) (*ecdsa.PublicKey, error) {
	if k.Crv == "" || k.X == "" || k.Y == "" {
		return nil, errors.New("ecdh_jwe_enc: JWK missing crv/x/y")
	}
	var curve elliptic.Curve
	var ecdhCurve ecdh.Curve
	switch k.Crv {
	case "P-256":
		curve, ecdhCurve = elliptic.P256(), ecdh.P256()
	case "P-384":
		curve, ecdhCurve = elliptic.P384(), ecdh.P384()
	case "P-521":
		curve, ecdhCurve = elliptic.P521(), ecdh.P521()
	default:
		return nil, fmt.Errorf("ecdh_jwe_enc: unsupported crv %q", k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("ecdh_jwe_enc: decode x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("ecdh_jwe_enc: decode y: %w", err)
	}
	// Validate the point lies on the curve via crypto/ecdh (rejects
	// invalid-curve attacks) by parsing the uncompressed SEC1 encoding
	// 0x04 || X || Y, each coordinate left-padded to the curve's byte
	// length. go-jose's ECDH-ES recipient wants an *ecdsa.PublicKey, so
	// we hand it back the ecdsa form after validation.
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(xb) > byteLen || len(yb) > byteLen {
		return nil, errors.New("ecdh_jwe_enc: coordinate exceeds curve size")
	}
	point := make([]byte, 1+2*byteLen)
	point[0] = 4
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	x.FillBytes(point[1 : 1+byteLen])
	y.FillBytes(point[1+byteLen:])
	if _, err := ecdhCurve.NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("ecdh_jwe_enc: invalid EC point: %w", err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
