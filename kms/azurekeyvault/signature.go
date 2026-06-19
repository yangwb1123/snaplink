package azurekeyvault

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// signatureAlgorithm maps the public key type + requested hash + padding to
// the Azure SignatureAlgorithm. For EC it also returns the curve (so Sign can
// convert the raw R||S to DER); for RSA the returned curve is nil. The
// hash<->curve pairing is enforced fail-closed.
//
//	P-256 + SHA-256          -> ES256  (curve = P-256)
//	P-384 + SHA-384          -> ES384  (curve = P-384)
//	P-521 + SHA-512          -> ES512  (curve = P-521)
//	RSA   + SHA-256, !pss    -> RS256  (curve = nil)
//	RSA   + SHA-256,  pss    -> PS256  (curve = nil)
func signatureAlgorithm(pub crypto.PublicKey, hash crypto.Hash, pss bool) (azkeys.SignatureAlgorithm, elliptic.Curve, error) {
	switch pk := pub.(type) {
	case *ecdsa.PublicKey:
		// The curve fixes the JWS hash. Reject any other pairing fail-closed —
		// matching the pkcs11/awskms/gcpkms peers — so a direct crypto.Signer
		// caller cannot sign a digest that would verify under a different hash
		// than the ES* alg the JWKS publishes. The !=want check also subsumes
		// the HashFunc()==0 (Ed25519-shaped) rejection for EC keys.
		switch pk.Curve {
		case elliptic.P256():
			if hash != crypto.SHA256 {
				return "", nil, fmt.Errorf("azurekeyvault: %w: P-256 key requires SHA-256 (ES256), got %v", ErrUnsupportedKey, hash)
			}
			return azkeys.SignatureAlgorithmES256, elliptic.P256(), nil
		case elliptic.P384():
			if hash != crypto.SHA384 {
				return "", nil, fmt.Errorf("azurekeyvault: %w: P-384 key requires SHA-384 (ES384), got %v", ErrUnsupportedKey, hash)
			}
			return azkeys.SignatureAlgorithmES384, elliptic.P384(), nil
		case elliptic.P521():
			if hash != crypto.SHA512 {
				return "", nil, fmt.Errorf("azurekeyvault: %w: P-521 key requires SHA-512 (ES512), got %v", ErrUnsupportedKey, hash)
			}
			return azkeys.SignatureAlgorithmES512, elliptic.P521(), nil
		default:
			return "", nil, fmt.Errorf("azurekeyvault: %w: unsupported ECDSA curve %s", ErrUnsupportedKey, pk.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		// The JWS RSA issuers sign over SHA-256 only (RS256 / PS256). The RSA
		// key size (2048/3072/4096) is orthogonal to the hash.
		if hash != crypto.SHA256 {
			return "", nil, fmt.Errorf("azurekeyvault: %w: RSA with hash %v (only SHA-256 / RS256|PS256 supported)", ErrUnsupportedKey, hash)
		}
		if pss {
			return azkeys.SignatureAlgorithmPS256, nil, nil
		}
		return azkeys.SignatureAlgorithmRS256, nil, nil
	default:
		// EdDSA / Ed25519 lands here (Public() never returns an ed25519 key —
		// jwkToPublic rejects non-EC/RSA — but a hypothetical key type is
		// caught regardless): Azure Key Vault has no EdDSA key type.
		return "", nil, fmt.Errorf("azurekeyvault: %w: public key type %T (Azure Key Vault has no Ed25519/EdDSA key)", ErrUnsupportedKey, pub)
	}
}

// ecdsaDERSignature is the ASN.1 SEQUENCE { r INTEGER, s INTEGER } the stdlib
// crypto.Signer ECDSA contract mandates (and ecdsa.VerifyASN1 consumes).
type ecdsaDERSignature struct{ R, S *big.Int }

// rawECDSAToDER converts Azure's raw fixed-width R||S signature (RFC 7518
// §3.4 / IEEE-P1363, what Key Vault returns for an ES* Sign) into the ASN.1
// DER form the crypto.Signer ECDSA contract requires. The raw signature is
// exactly 2*ceil(bits/8) bytes — R then S, each left-padded to the curve's
// coordinate octet length (P-256 -> 32, P-384 -> 48, P-521 -> 66) — so we
// split it in half and DER-encode the two integers. It rejects a length that
// does not match the curve rather than emit a signature no verifier accepts.
// This is the INVERSE of cryptosigner's derToJWSSignature: doing it here lets
// this type stay a faithful crypto.Signer that round-trips against
// ecdsa.VerifyASN1, then the bridge re-splits DER -> R||S for the JWS wire.
func rawECDSAToDER(raw []byte, curve elliptic.Curve) ([]byte, error) {
	coordLen := (curve.Params().BitSize + 7) / 8
	if len(raw) != 2*coordLen {
		return nil, fmt.Errorf("azurekeyvault: raw ECDSA signature length %d, want %d (2*%d for %s)",
			len(raw), 2*coordLen, coordLen, curve.Params().Name)
	}
	r := new(big.Int).SetBytes(raw[:coordLen])
	sv := new(big.Int).SetBytes(raw[coordLen:])
	if r.Sign() <= 0 || sv.Sign() <= 0 {
		return nil, errors.New("azurekeyvault: vault returned non-positive R or S")
	}
	der, err := asn1.Marshal(ecdsaDERSignature{R: r, S: sv})
	if err != nil {
		return nil, fmt.Errorf("azurekeyvault: marshal ECDSA DER: %w", err)
	}
	return der, nil
}
