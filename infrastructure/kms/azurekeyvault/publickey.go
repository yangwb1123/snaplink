//go:build !no_kms_azurekeyvault

package azurekeyvault

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// jwkToPublic assembles a stdlib public key from the vault's JSON Web Key.
// Azure returns the key components as raw big-endian octet strings (the JWK
// base64url decoded form): RSA modulus N + exponent E, or EC affine
// coordinates X/Y on a named curve. RSA-HSM / EC-HSM keys (the HSM-backed,
// non-exportable, FIPS-gate variants) carry the SAME public components and
// are accepted identically. Symmetric (oct) and the non-JWS P-256K curve are
// rejected with ErrUnsupportedKey.
func jwkToPublic(jwk *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if jwk == nil || jwk.Kty == nil {
		return nil, fmt.Errorf("azurekeyvault: %w: key bundle has no key type", ErrUnsupportedKey)
	}
	switch *jwk.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		if len(jwk.N) == 0 || len(jwk.E) == 0 {
			return nil, fmt.Errorf("azurekeyvault: %w: RSA JWK missing modulus or exponent", ErrUnsupportedKey)
		}
		// E is a big-endian octet string; fold it into an int. RSA public
		// exponents (65537) fit comfortably, but guard against a value that
		// would overflow the platform int rather than truncate it.
		eBig := new(big.Int).SetBytes(jwk.E)
		if !eBig.IsInt64() || eBig.Int64() > int64(int(^uint(0)>>1)) || eBig.Sign() <= 0 {
			return nil, fmt.Errorf("azurekeyvault: %w: RSA public exponent out of range", ErrUnsupportedKey)
		}
		// Validate the exponent is a cryptographically valid RSA public
		// exponent on the FULL value (before the int truncation below). Unlike
		// awskms/gcpkms, which parse a DER SubjectPublicKeyInfo through
		// x509.ParsePKIXPublicKey and inherit its exponent checks, this module
		// parses the RAW JWK N/E and so bypasses x509's validation — it MUST
		// reject these itself. e<3 (e=1 is the identity exponent: ciphertext ==
		// plaintext, trivially forgeable; e=2 is below the minimum) or an even e
		// (RSA requires gcd(e, phi(N))==1, and phi(N) is even, so an even e is
		// never coprime → invalid) is never a valid RSA public exponent. This
		// keeps legitimate small odd exponents (e=3, e=65537). A misbehaving /
		// compromised / misconfigured vault returning E=0x01 would otherwise
		// yield an rsa.PublicKey{E:1} published in JWKS → forgeable tokens.
		if eBig.Cmp(big.NewInt(3)) < 0 || eBig.Bit(0) == 0 {
			return nil, fmt.Errorf("azurekeyvault: %w: invalid RSA public exponent (must be odd and >= 3)", ErrUnsupportedKey)
		}
		n := new(big.Int).SetBytes(jwk.N)
		// Defense-in-depth modulus floor: reject a sub-2048-bit RSA key. The
		// production path is already saved by cryptosigner.RSA's
		// N.BitLen()>=2048 startup check, but a DIRECT crypto.Signer consumer of
		// this Signer bypasses that — so floor it locally too, mirroring the
		// cryptosigner + spiffe trust-bundle 2048-bit floor (RFC 7518 §3.3).
		if n.BitLen() < minRSABits {
			return nil, fmt.Errorf("azurekeyvault: %w: RSA modulus is %d bits, want >= %d", ErrUnsupportedKey, n.BitLen(), minRSABits)
		}
		return &rsa.PublicKey{
			N: n,
			E: int(eBig.Int64()),
		}, nil
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		if jwk.Crv == nil {
			return nil, fmt.Errorf("azurekeyvault: %w: EC JWK missing curve", ErrUnsupportedKey)
		}
		curve, err := curveForName(*jwk.Crv)
		if err != nil {
			return nil, err
		}
		if len(jwk.X) == 0 || len(jwk.Y) == 0 {
			return nil, fmt.Errorf("azurekeyvault: %w: EC JWK missing X or Y coordinate", ErrUnsupportedKey)
		}
		pub := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(jwk.X),
			Y:     new(big.Int).SetBytes(jwk.Y),
		}
		// Reject a point that is not actually on the curve — a malformed JWK
		// must fail loud, never produce a key that signs garbage. IsOnCurve is
		// the direct on-curve validator for a raw JWK X/Y: it rejects off-curve
		// points, out-of-range coordinates (each must lie in [0, P)), and the
		// point at infinity (0,0) — the three checks that matter here, all
		// empirically confirmed. Go 1.26 marks elliptic.Curve.IsOnCurve
		// Deprecated ("low-level unsafe API"), but it remains functionally
		// correct: awskms/gcpkms sidestep it because they parse a DER
		// SubjectPublicKeyInfo via x509.ParsePKIXPublicKey (which validates
		// internally), whereas this module parses the raw EC components, so the
		// explicit on-curve check is necessary, not optional.
		if !curve.IsOnCurve(pub.X, pub.Y) { //nolint:staticcheck // intentional: raw-JWK on-curve validation (see comment above); deprecated but functionally correct
			return nil, fmt.Errorf("azurekeyvault: %w: EC public point is not on curve %s", ErrUnsupportedKey, curve.Params().Name)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("azurekeyvault: %w: key type %s", ErrUnsupportedKey, *jwk.Kty)
	}
}

// curveForName maps the Azure JWK curve name to the stdlib elliptic.Curve.
// Only the three NIST curves that carry a JWS ECDSA alg are supported;
// P-256K (secp256k1) is not a JWS-standard curve and is rejected.
func curveForName(name azkeys.CurveName) (elliptic.Curve, error) {
	switch name {
	case azkeys.CurveNameP256:
		return elliptic.P256(), nil
	case azkeys.CurveNameP384:
		return elliptic.P384(), nil
	case azkeys.CurveNameP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("azurekeyvault: %w: EC curve %s (only P-256/P-384/P-521 carry a JWS alg)", ErrUnsupportedKey, name)
	}
}
