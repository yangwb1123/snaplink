// Signing-key aggregation: JWK key-type constants and decoders.
package sso

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/snaplink/sso/core"
)

// JWK key-type discriminators (RFC 7517 §4.1).
const (
	jwkKtyOKP         = "OKP"  // Ed25519 (EdDSA)
	jwkKtyEC          = "EC"   // P-256 (ES256)
	jwkKtyRSA         = "RSA"  // RS256 | PS256
	jwkCrvP256        = "P-256"
	rsaMinPeerKeyBits = 2048
)

// decodeEd25519JWK reconstructs an ed25519.PublicKey from an OKP/Ed25519 JWK.
func decodeEd25519JWK(jwk core.JWK) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, &decodeError{kid: jwk.Kid, gotLen: len(raw)}
	}
	return ed25519.PublicKey(raw), nil
}

// decodeECDSAJWK reconstructs a P-256 *ecdsa.PublicKey from an EC JWK.
func decodeECDSAJWK(jwk core.JWK) (*ecdsa.PublicKey, error) {
	if jwk.Crv != jwkCrvP256 {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: unsupported crv %q (want %s)", jwk.Kid, jwk.Crv, jwkCrvP256)
	}
	if jwk.X == "" || jwk.Y == "" {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: missing x/y", jwk.Kid)
	}
	xb, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: decode x: %w", jwk.Kid, err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: decode y: %w", jwk.Kid, err)
	}
	curve := elliptic.P256()
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(xb) > byteLen || len(yb) > byteLen {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: coordinate exceeds curve size", jwk.Kid)
	}
	point := make([]byte, 1+2*byteLen)
	point[0] = 4
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	x.FillBytes(point[1 : 1+byteLen])
	y.FillBytes(point[1+byteLen:])
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: invalid EC point: %w", jwk.Kid, err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// decodeRSAJWK reconstructs an *rsa.PublicKey from an RSA JWK.
func decodeRSAJWK(jwk core.JWK) (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: missing n/e", jwk.Kid)
	}
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: decode n: %w", jwk.Kid, err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: decode e: %w", jwk.Kid, err)
	}
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() < rsaMinPeerKeyBits {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: modulus is %d bits, minimum is %d", jwk.Kid, n.BitLen(), rsaMinPeerKeyBits)
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: public exponent too large", jwk.Kid)
	}
	ev := e.Int64()
	if ev < 3 || ev&1 == 0 {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: degenerate public exponent %d", jwk.Kid, ev)
	}
	return &rsa.PublicKey{N: n, E: int(ev)}, nil
}

// decodeError reports a peer JWK whose decoded public key is the wrong length.
type decodeError struct {
	kid    string
	gotLen int
}

func (e *decodeError) Error() string {
	return "signingkeys: peer key " + e.kid + ": unexpected ed25519 public key length"
}
