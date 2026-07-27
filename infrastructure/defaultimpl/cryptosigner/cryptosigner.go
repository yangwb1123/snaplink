// Package cryptosigner bridges any stdlib [crypto.Signer] into the
// defaultimpl JWT-issuer signing seams (Ed25519Signer / ECDSASigner /
// RSASigner), so an operator can back token signing with a KMS / HSM /
// PKCS#11 key whose private half never enters this process.
//
// crypto.Signer is the universal abstraction every cloud-KMS SDK and
// PKCS#11 library satisfies (or is trivially wrapped to): AWS KMS, GCP
// KMS, Azure Key Vault, and ThalesGroup/crypto11 (YubiHSM / SoftHSM /
// Thales / Entrust) all expose one. By depending only on crypto.Signer
// this package keeps the (heavy, vendor-specific) KMS SDK out of the SSO
// module's go.mod — the operator constructs their crypto.Signer in their
// own cmd binary and passes it here, mirroring how the repo keeps etcd
// and push-transport SDKs in cmd rather than the SPI.
//
// The bridge handles the one non-obvious impedance mismatch: cloud KMS
// and HSM backends return ECDSA signatures as ASN.1 DER, whereas JWS
// ES256 (RFC 7518 §3.4) mandates the fixed-width R||S form — [ECDSA]
// converts between them. Ed25519 and RSA signatures pass through with a
// length / parameter check.
//
// Wiring (ES256, AWS KMS shown schematically):
//
//	kmsSigner := myawskms.NewSigner(ctx, keyARN) // operator's crypto.Signer, in cmd
//	sgn, pub, err := cryptosigner.ECDSA(kmsSigner)
//	if err != nil { ... }
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(sgn, pub, keyARN),
//	)
//
// All three constructors validate the supplied signer's public key shape
// at wiring time and fail closed — a misconfigured signer is rejected at
// startup, never at the first token issuance.
package cryptosigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

// RSA alg names (canonical JWS values, RFC 7518 §3.3/§3.5). Declared here
// so callers needn't reach into defaultimpl's unexported constants.
const (
	AlgRS256 = "RS256" // RSASSA-PKCS1-v1_5 + SHA-256
	AlgPS256 = "PS256" // RSASSA-PSS + SHA-256 (FAPI-preferred)
)

// p256CoordinateBytes is the fixed octet length of each P-256 scalar in
// the JWS R||S encoding (RFC 7518 §3.4).
const p256CoordinateBytes = 32

// minRSABits mirrors NewRSAJWTIssuer's floor. The external-signer wiring
// path skips that check (the key is out-of-process), so we enforce it
// here instead.
const minRSABits = 2048

// Interface guards: the bridges satisfy the defaultimpl signing seams.
var (
	_ defaultimpl.Ed25519Signer = ed25519Bridge{}
	_ defaultimpl.ECDSASigner   = ecdsaBridge{}
	_ defaultimpl.RSASigner     = rsaBridge{}
)

// Ed25519 adapts an Ed25519-keyed crypto.Signer into a
// [defaultimpl.Ed25519Signer]. It returns the signer's public key
// (for WithEd25519ExternalSigner / JWKS publication). Errors if the
// signer's public key is not an Ed25519 key.
func Ed25519(s crypto.Signer) (defaultimpl.Ed25519Signer, ed25519.PublicKey, error) {
	if s == nil {
		return nil, nil, errors.New("cryptosigner: nil signer")
	}
	pub, ok := s.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("cryptosigner: signer public key is %T, want ed25519.PublicKey", s.Public())
	}
	return ed25519Bridge{s: s}, pub, nil
}

type ed25519Bridge struct{ s crypto.Signer }

// CryptoSigner returns the UNDERLYING out-of-process crypto.Signer (the
// KMS/HSM key) this bridge wraps, satisfying defaultimpl's unexported
// cryptoSignerProvider seam so the issuer's CryptoSigner() accessor hands
// SAML 2.0 / XML-DSig the SAME key that's in JWKS — never the JWS-adapting
// bridge. The bridge's Sign DOES JWS-specific work (DER->R‖S for ECDSA,
// alg-aware padding for RSA) that the DSig pre-hashed-digest path must NOT
// go through; exposing the raw crypto.Signer sidesteps that, letting the
// DSig stack drive the key under its own signature method. The private key
// material never crosses the process boundary either way — a crypto.Signer
// only signs.
func (b ed25519Bridge) CryptoSigner() crypto.Signer { return b.s }

func (b ed25519Bridge) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Ed25519 signs the message directly (no pre-hash): crypto.Signer
	// implementations require opts.HashFunc() == crypto.Hash(0).
	sig, err := b.s.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("cryptosigner: ed25519 sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("cryptosigner: ed25519 signature length %d, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// ECDSA adapts a P-256-keyed crypto.Signer into a
// [defaultimpl.ECDSASigner], converting the ASN.1 DER signature the
// signer returns into the fixed-width R||S form ES256 requires. Errors
// if the public key is not ECDSA or not on the P-256 curve (the only
// curve the ES256 issuer supports).
func ECDSA(s crypto.Signer) (defaultimpl.ECDSASigner, *ecdsa.PublicKey, error) {
	if s == nil {
		return nil, nil, errors.New("cryptosigner: nil signer")
	}
	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("cryptosigner: signer public key is %T, want *ecdsa.PublicKey", s.Public())
	}
	if pub.Curve != elliptic.P256() {
		return nil, nil, fmt.Errorf("cryptosigner: ECDSA curve is %s, want P-256 (ES256)", pub.Curve.Params().Name)
	}
	return ecdsaBridge{s: s}, pub, nil
}

type ecdsaBridge struct{ s crypto.Signer }

// CryptoSigner returns the underlying out-of-process crypto.Signer (the
// KMS/HSM key) for the SAML/XML-DSig seam — see ed25519Bridge.CryptoSigner.
// Critically for ECDSA: the SAML/DSig consumer gets the raw signer whose
// Sign returns ASN.1 DER (what KMS/HSM emit and what the XML-DSig stack
// expects), NOT this bridge's JWS R‖S conversion.
func (b ecdsaBridge) CryptoSigner() crypto.Signer { return b.s }

func (b ecdsaBridge) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	der, err := b.s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cryptosigner: ecdsa sign: %w", err)
	}
	return derToJWSSignature(der)
}

// ecdsaDERSignature is the ASN.1 SEQUENCE { r INTEGER, s INTEGER } that
// crypto/ecdsa and every KMS/HSM ECDSA backend emit.
type ecdsaDERSignature struct{ R, S *big.Int }

// derToJWSSignature converts an ASN.1 DER ECDSA signature into the
// fixed-width 64-byte R||S form (RFC 7518 §3.4), left-padding each
// scalar to 32 octets. It rejects malformed input rather than emitting a
// signature no verifier would accept.
func derToJWSSignature(der []byte) ([]byte, error) {
	var sig ecdsaDERSignature
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("cryptosigner: parse ECDSA DER signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("cryptosigner: trailing bytes after ECDSA DER signature")
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("cryptosigner: ECDSA signature has non-positive R or S")
	}
	if sig.R.BitLen() > p256CoordinateBytes*8 || sig.S.BitLen() > p256CoordinateBytes*8 {
		return nil, errors.New("cryptosigner: ECDSA R/S exceeds P-256 coordinate size")
	}
	out := make([]byte, 2*p256CoordinateBytes)
	sig.R.FillBytes(out[:p256CoordinateBytes])
	sig.S.FillBytes(out[p256CoordinateBytes:])
	return out, nil
}

// RSA adapts an RSA-keyed crypto.Signer into a [defaultimpl.RSASigner].
// alg selects the padding scheme — [AlgRS256] (PKCS1v15) or [AlgPS256]
// (PSS) — and MUST match the issuer's WithRSAAlg, else minted signatures
// won't verify. Errors if the public key is not RSA, the key is under
// 2048 bits, or alg is unsupported.
func RSA(s crypto.Signer, alg string) (defaultimpl.RSASigner, *rsa.PublicKey, error) {
	if s == nil {
		return nil, nil, errors.New("cryptosigner: nil signer")
	}
	pub, ok := s.Public().(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("cryptosigner: signer public key is %T, want *rsa.PublicKey", s.Public())
	}
	if pub.N.BitLen() < minRSABits {
		return nil, nil, fmt.Errorf("cryptosigner: RSA key is %d bits, want >= %d", pub.N.BitLen(), minRSABits)
	}
	var pss bool
	switch alg {
	case AlgRS256:
		pss = false
	case AlgPS256:
		pss = true
	default:
		return nil, nil, fmt.Errorf("cryptosigner: RSA alg %q unsupported (want %s or %s)", alg, AlgRS256, AlgPS256)
	}
	return rsaBridge{s: s, pss: pss}, pub, nil
}

type rsaBridge struct {
	s   crypto.Signer
	pss bool
}

// CryptoSigner returns the underlying out-of-process crypto.Signer (the
// KMS/HSM key) for the SAML/XML-DSig seam — see ed25519Bridge.CryptoSigner.
// The SAML/DSig consumer picks its own RSA signature method (PKCS1v15 vs
// PSS) via crypto.SignerOpts at sign time, independent of this bridge's
// configured JWS padding.
func (b rsaBridge) CryptoSigner() crypto.Signer { return b.s }

func (b rsaBridge) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	// opts only steer an in-process software signer; a KMS/HSM-backed
	// crypto.Signer applies its own configured scheme. PSS salt length =
	// hash length matches what go-jose verifies (PSSSaltLengthAuto) and
	// what AWS KMS RSASSA_PSS_SHA_256 produces.
	var opts crypto.SignerOpts = crypto.SHA256
	if b.pss {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	}
	sig, err := b.s.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		return nil, fmt.Errorf("cryptosigner: rsa sign: %w", err)
	}
	return sig, nil
}
