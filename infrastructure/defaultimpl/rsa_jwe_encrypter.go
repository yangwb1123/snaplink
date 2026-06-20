package defaultimpl

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/go-jose/go-jose/v4"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// RSAJWEResponseEncrypter wraps server-produced response artifacts (ID
// Token JWS, signed/JSON userinfo) in a JWE addressed to the relying
// party's RSA public encryption key. It is the response-direction
// counterpart to [RSAJWEDecrypter]: the same cipher suite — RSA-OAEP-256
// for key wrapping + A256GCM for content encryption — that FAPI 2.0
// recommends and every off-the-shelf JOSE client emits by default.
//
// Stateless: it holds no key of its own. The recipient key is selected
// per-call from the client's registered JWKS (Client.JWKS), so a single
// encrypter serves every client.
//
// Implements [security.JWEEncrypter].
type RSAJWEResponseEncrypter struct{}

// NewRSAJWEResponseEncrypter returns a response encrypter for the
// RSA-OAEP-256 + A256GCM suite.
func NewRSAJWEResponseEncrypter() *RSAJWEResponseEncrypter {
	return &RSAJWEResponseEncrypter{}
}

var _ security.JWEEncrypter = (*RSAJWEResponseEncrypter)(nil)

// errNoEncKey signals no usable `use:enc` RSA key in the recipient
// JWKS. Kept internal — callers MUST NOT surface it distinctly from a
// crypto failure (oracle-leak hardening).
var errNoEncKey = errors.New("rsa_jwe_enc: no usable RSA encryption key in recipient JWKS")

// Encrypt wraps plaintext in a JWE for the recipient. Only RSA-OAEP-256
// + A256GCM are accepted; any other alg/enc is rejected so the AS never
// silently downgrades to a weaker suite a client might register.
func (e *RSAJWEResponseEncrypter) Encrypt(_ context.Context, plaintext []byte, recipientJWKS []core.JWK, alg, enc string) (string, error) {
	if alg != "RSA-OAEP-256" {
		return "", fmt.Errorf("rsa_jwe_enc: unsupported alg %q", alg)
	}
	if enc != "A256GCM" {
		return "", fmt.Errorf("rsa_jwe_enc: unsupported enc %q", enc)
	}
	pub, kid, err := selectRSAEncKey(recipientJWKS)
	if err != nil {
		return "", err
	}

	recipient := jose.Recipient{
		Algorithm: jose.RSA_OAEP_256,
		Key:       pub,
		KeyID:     kid,
	}
	enc256 := jose.A256GCM
	encrypter, err := jose.NewEncrypter(enc256, recipient, nil)
	if err != nil {
		return "", fmt.Errorf("rsa_jwe_enc: new encrypter: %w", err)
	}
	obj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("rsa_jwe_enc: encrypt: %w", err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("rsa_jwe_enc: serialize: %w", err)
	}
	return compact, nil
}

// SupportedAlgs returns the JWE `alg` values this encrypter produces.
func (e *RSAJWEResponseEncrypter) SupportedAlgs() []string {
	return []string{"RSA-OAEP-256"}
}

// SupportedEncs returns the JWE `enc` values this encrypter produces.
func (e *RSAJWEResponseEncrypter) SupportedEncs() []string {
	return []string{"A256GCM"}
}

// selectRSAEncKey picks the recipient RSA public key from the client
// JWKS. Preference order: an RSA key with use:"enc" (and matching
// alg when present) wins; an RSA key with no `use` (dual-use) is
// accepted as a fallback. Signing-only keys (use:"sig") are skipped —
// encrypting to a signing key is a misconfiguration. Returns the
// selected key's kid so the JWE protected header references it (RPs
// with multiple keys disambiguate by kid).
func selectRSAEncKey(jwks []core.JWK) (*rsa.PublicKey, string, error) {
	var fallback *core.JWK
	for i := range jwks {
		k := &jwks[i]
		if k.Kty != "RSA" {
			continue
		}
		if k.Use == "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != "RSA-OAEP-256" {
			continue
		}
		if k.Use == "enc" {
			pub, err := rsaPublicFromJWK(k)
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
		pub, err := rsaPublicFromJWK(fallback)
		if err == nil {
			return pub, fallback.Kid, nil
		}
	}
	return nil, "", errNoEncKey
}

// rsaPublicFromJWK reconstructs an *rsa.PublicKey from a JWK's base64url
// N + E parameters (RFC 7518 §6.3).
func rsaPublicFromJWK(k *core.JWK) (*rsa.PublicKey, error) {
	if k.N == "" || k.E == "" {
		return nil, errors.New("rsa_jwe_enc: JWK missing n/e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("rsa_jwe_enc: decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("rsa_jwe_enc: decode e: %w", err)
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > 1<<31 {
		return nil, errors.New("rsa_jwe_enc: invalid exponent")
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}
	if pub.N.Sign() <= 0 {
		return nil, errors.New("rsa_jwe_enc: invalid modulus")
	}
	return pub, nil
}
