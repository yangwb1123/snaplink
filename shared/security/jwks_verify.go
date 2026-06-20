package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/snaplink/sso/shared/core"
)

// JWS asymmetric algorithm identifiers (RFC 7518 §3.1). `none` and every
// HS* (symmetric) alg are DELIBERATELY absent: a SPIFFE trust bundle is
// always asymmetric, and admitting a symmetric alg would open the
// public-key-as-HMAC-secret confusion attack.
const (
	jwsAlgEdDSA = "EdDSA"
	jwsAlgES256 = "ES256"
	jwsAlgES384 = "ES384"
	jwsAlgES512 = "ES512"
	jwsAlgRS256 = "RS256"
	jwsAlgRS384 = "RS384"
	jwsAlgRS512 = "RS512"
	jwsAlgPS256 = "PS256"
	jwsAlgPS384 = "PS384"
	jwsAlgPS512 = "PS512"
)

// VerifyCompactJWS verifies a 3-segment compact JWS against a set of
// asymmetric JWKs, selecting the verification key by header `kid` and the
// verification algorithm by header `alg`. It is the single shared "verify
// an externally-minted JWT against a trust-bundle JWKS" primitive — the
// SPIFFE JWT-SVID acceptance path reuses it instead of hand-rolling a
// second copy of signature verification. It uses only Go std-lib crypto
// (the same primitives the in-process JWT issuers already use:
// ed25519.Verify / ecdsa.Verify / rsa.VerifyPKCS1v15 / rsa.VerifyPSS).
//
// Security contract (mirrors the issuers' Validate gates, AGENTS.md §2
// "alg + typ allowlist on Validate"):
//
//   - alg-confusion defense: the caller passes the EXPLICIT allowlist of
//     asymmetric algs the trust bundle uses. The header `alg` MUST be in
//     it BEFORE any signature work. `alg: none` (an unsigned token) and
//     every symmetric HS* alg are therefore rejected up front — an
//     attacker cannot downgrade an asymmetric trust bundle to "no
//     signature" nor trick the verifier into treating an RSA modulus as
//     an HMAC secret (the classic RS/HS confusion). The allowlist NEVER
//     contains a symmetric alg (VerifyCompactJWS refuses such a set).
//   - kid binding: the header `kid` selects the verification key. An
//     empty header kid is tolerated only when the bundle holds exactly
//     one key (single-key SPIRE bundles often omit kid); a multi-key
//     bundle with an empty header kid is ambiguous and fails closed. An
//     unknown kid fails closed.
//   - key/alg consistency: the matched JWK's kty/crv MUST match what the
//     header `alg` demands, so a kid cannot name a key of a different
//     type than the alg (a second alg-confusion seam). EC points are
//     verified on-curve (invalid-curve-attack defense).
//
// Returns the raw (base64url-decoded) payload bytes on success so the
// caller parses claims itself. Every failure returns a non-nil error;
// callers that must avoid an oracle (token-exchange) collapse ALL of
// them into one opaque response.
func VerifyCompactJWS(compact string, keys []core.JWK, allowedAlgs map[string]struct{}) ([]byte, error) {
	if len(allowedAlgs) == 0 {
		return nil, errors.New("jws: empty alg allowlist")
	}
	for alg := range allowedAlgs {
		// A symmetric alg in the allowlist would let an attacker forge a
		// token using a PUBLIC key as the HMAC secret. Refuse to operate
		// with such an allowlist at all rather than silently honor it.
		if !isAsymmetricJWSAlg(alg) {
			return nil, fmt.Errorf("jws: non-asymmetric alg %q forbidden in allowlist", alg)
		}
	}

	dot1, dot2 := -1, -1
	for i := 0; i < len(compact); i++ {
		if compact[i] != '.' {
			continue
		}
		switch {
		case dot1 < 0:
			dot1 = i
		case dot2 < 0:
			dot2 = i
		default:
			return nil, errors.New("jws: not a 3-segment compact JWS")
		}
	}
	if dot1 < 0 || dot2 < 0 || dot2 == len(compact)-1 {
		return nil, errors.New("jws: not a 3-segment compact JWS")
	}
	headerSeg := compact[:dot1]
	payloadSeg := compact[dot1+1 : dot2]
	sigSeg := compact[dot2+1:]
	signingInput := []byte(compact[:dot2])

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerSeg)
	if err != nil {
		return nil, fmt.Errorf("jws: header decode: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("jws: header parse: %w", err)
	}
	// alg gate BEFORE any signature verification (RFC 9068 §4 discipline).
	// `alg: none` lands here and is rejected because "none" is never in
	// the asymmetric allowlist.
	if _, ok := allowedAlgs[h.Alg]; !ok {
		return nil, fmt.Errorf("jws: alg %q not in allowlist", h.Alg)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigSeg)
	if err != nil {
		return nil, fmt.Errorf("jws: signature decode: %w", err)
	}

	jwk, err := selectVerifyJWK(keys, h.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifyJWSWithJWK(h.Alg, jwk, signingInput, sig); err != nil {
		return nil, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadSeg)
	if err != nil {
		return nil, fmt.Errorf("jws: payload decode: %w", err)
	}
	return payload, nil
}

// selectVerifyJWK resolves the verification key by kid. Empty kid is
// accepted only when the bundle has exactly one key.
func selectVerifyJWK(keys []core.JWK, kid string) (core.JWK, error) {
	if len(keys) == 0 {
		return core.JWK{}, errors.New("jws: empty JWKS")
	}
	if kid == "" {
		if len(keys) == 1 {
			return keys[0], nil
		}
		return core.JWK{}, errors.New("jws: empty kid with multi-key JWKS is ambiguous")
	}
	for _, k := range keys {
		if k.Kid == kid {
			return k, nil
		}
	}
	return core.JWK{}, fmt.Errorf("jws: no JWK matches kid %q", kid)
}

// verifyJWSWithJWK converts the JWK to its public key and verifies the
// signature with the std-lib primitive matching alg. The JWK's own
// kty/crv MUST be consistent with the header alg.
func verifyJWSWithJWK(alg string, jwk core.JWK, signingInput, sig []byte) error {
	switch alg {
	case jwsAlgEdDSA:
		pub, err := ed25519PublicFromJWK(jwk)
		if err != nil {
			return err
		}
		if !ed25519.Verify(pub, signingInput, sig) {
			return errors.New("jws: EdDSA signature invalid")
		}
		return nil

	case jwsAlgES256, jwsAlgES384, jwsAlgES512:
		pub, coordBytes, err := ecdsaPublicFromJWK(alg, jwk)
		if err != nil {
			return err
		}
		// JWS ES* signatures are the fixed-width R||S concatenation (RFC
		// 7518 §3.4), NOT ASN.1 DER. Reject any other length so a DER
		// signature is never silently accepted.
		if len(sig) != 2*coordBytes {
			return errors.New("jws: ES signature wrong length")
		}
		digest := digestOf(alg, signingInput)
		r := new(big.Int).SetBytes(sig[:coordBytes])
		s := new(big.Int).SetBytes(sig[coordBytes:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errors.New("jws: ES signature invalid")
		}
		return nil

	case jwsAlgRS256, jwsAlgRS384, jwsAlgRS512:
		pub, err := rsaPublicFromJWK(jwk)
		if err != nil {
			return err
		}
		hash := hashForAlg(alg)
		if err := rsa.VerifyPKCS1v15(pub, hash, digestOf(alg, signingInput), sig); err != nil {
			return errors.New("jws: RS signature invalid")
		}
		return nil

	case jwsAlgPS256, jwsAlgPS384, jwsAlgPS512:
		pub, err := rsaPublicFromJWK(jwk)
		if err != nil {
			return err
		}
		hash := hashForAlg(alg)
		// Interop: standard PS256 signers (go-jose / golang-jwt, and thus
		// SPIRE) sign with the MAXIMUM salt (PSSSaltLengthAuto = (keyBits-1)/8
		// - hashLen - 2, e.g. 222 bytes for RSA-2048/SHA-256), NOT the
		// hash-length salt. Verifying with PSSSaltLengthEqualsHash would
		// reject every such valid SVID. PSSSaltLengthAuto on the VERIFY side
		// auto-detects the salt length present in the signature, accepting the
		// full RFC 7518 §3.5 valid range. This is verification-only; any
		// signing path keeps its own salt choice.
		if err := rsa.VerifyPSS(pub, hash, digestOf(alg, signingInput), sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       hash,
		}); err != nil {
			return errors.New("jws: PS signature invalid")
		}
		return nil

	default:
		// Unreachable: the allowlist gate already rejected anything else.
		// Kept as a fail-closed backstop.
		return fmt.Errorf("jws: unsupported alg %q", alg)
	}
}

// --- JWK → public key decoders (RFC 7518 §6) ---

func ed25519PublicFromJWK(jwk core.JWK) (ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, errors.New("jws: kid is not an Ed25519 OKP key")
	}
	xb, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(xb) != ed25519.PublicKeySize {
		return nil, errors.New("jws: malformed Ed25519 key")
	}
	return ed25519.PublicKey(xb), nil
}

// ecdsaPublicFromJWK returns the EC public key and the per-scalar byte
// width (= R/S length) for the named ES* alg.
func ecdsaPublicFromJWK(alg string, jwk core.JWK) (*ecdsa.PublicKey, int, error) {
	var curve elliptic.Curve
	var wantCrv string
	var coordBytes int
	switch alg {
	case jwsAlgES256:
		curve, wantCrv, coordBytes = elliptic.P256(), "P-256", 32
	case jwsAlgES384:
		curve, wantCrv, coordBytes = elliptic.P384(), "P-384", 48
	case jwsAlgES512:
		// P-521 scalars are 66 bytes (ceil(521/8)).
		curve, wantCrv, coordBytes = elliptic.P521(), "P-521", 66
	default:
		return nil, 0, fmt.Errorf("jws: unsupported EC alg %q", alg)
	}
	if jwk.Kty != "EC" || jwk.Crv != wantCrv {
		return nil, 0, fmt.Errorf("jws: kid is not a %s EC key", wantCrv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, 0, errors.New("jws: malformed EC x")
	}
	yb, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, 0, errors.New("jws: malformed EC y")
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	// Reject points not on the curve — defends against invalid-curve
	// attacks where an attacker supplies a crafted off-curve "public key".
	//nolint:staticcheck // raw on-curve check is the precise intent; crypto/ecdh would re-encode and hide the validation we need here.
	if !curve.IsOnCurve(x, y) {
		return nil, 0, errors.New("jws: EC point not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, coordBytes, nil
}

func rsaPublicFromJWK(jwk core.JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, errors.New("jws: kid is not an RSA key")
	}
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil || len(nb) == 0 {
		return nil, errors.New("jws: malformed RSA n")
	}
	// Externally-supplied verify keys (an operator's trust bundle is an
	// EXTERNAL trust boundary) must meet the same floor as keys we issue:
	// RFC 7518 §3.3 requires RSA >= 2048 bits, matching
	// defaultimpl.rsaMinKeyBits. 2048 bits = 256 bytes of modulus; a shorter
	// modulus is a weak key and is rejected, fail-closed. (Leading zero bytes
	// in a correctly base64url-encoded modulus are omitted, so a genuine
	// 2048-bit key is exactly 256 bytes.)
	if len(nb) < 256 {
		return nil, errors.New("jws: RSA key below 2048-bit minimum")
	}
	eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil || len(eb) == 0 {
		return nil, errors.New("jws: malformed RSA e")
	}
	// Accumulate into a big.Int first so an over-long encoding can't silently
	// overflow the int below (a 5+ byte E would wrap on 32-bit and is bogus
	// regardless). The decoded value is then range-checked before truncation.
	ebig := new(big.Int).SetBytes(eb)
	// Reject a degenerate public exponent at the gate, BEFORE any signature
	// work — the same floor the signing-key aggregation decoder and the RSA
	// issuer's AdoptVerifyKey enforce. e=1 makes RSA verification the identity
	// (sig^1 mod N == sig), so anyone could forge a "signature" with no private
	// key; an even e has no inverse modulo the (odd) RSA totient and is
	// cryptographically degenerate. Don't rely on crypto/rsa's own internal
	// e-check to backstop this: it is an implementation detail (and absent in
	// older Go / alternate verify backends), so this shared verifier (federation
	// / CAEP receiver / SPIFFE / JAR / private_key_jwt) enforces it explicitly,
	// fail-closed.
	if !ebig.IsInt64() {
		return nil, errors.New("jws: RSA exponent too large")
	}
	e := ebig.Int64()
	if e < 3 || e&1 == 0 {
		return nil, errors.New("jws: degenerate RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e)}, nil
}

func isAsymmetricJWSAlg(alg string) bool {
	switch alg {
	case jwsAlgEdDSA,
		jwsAlgES256, jwsAlgES384, jwsAlgES512,
		jwsAlgRS256, jwsAlgRS384, jwsAlgRS512,
		jwsAlgPS256, jwsAlgPS384, jwsAlgPS512:
		return true
	default:
		return false
	}
}

// AsymmetricJWSAlgs returns a fresh allowlist of the asymmetric JWS algs the
// RP-facing client-authentication + request-integrity paths accept:
// private_key_jwt client assertions (RFC 7523), JAR request objects (RFC
// 9101), and DPoP proofs (RFC 9449). It is the shared input to
// VerifyCompactJWS for all three, so they widen together and can never drift
// apart.
//
// The set is asymmetric-only BY CONSTRUCTION — `none` and every symmetric
// HS* alg are absent, so VerifyCompactJWS (which independently refuses any
// non-asymmetric alg in the allowlist) never opens the public-key-as-HMAC
// confusion attack. EdDSA stays first-class (the historical only-accepted
// alg) and ES256/384/512 + RS256 + PS256 are added — the algs real-world RP
// libraries and OpenID Federation chain-vouched keys overwhelmingly use
// (DPoP is almost always ES256; federation RP keys may be RSA/ECDSA).
//
// A fresh map is returned per call so a caller cannot mutate the shared
// allowlist of another path.
func AsymmetricJWSAlgs() map[string]struct{} {
	return map[string]struct{}{
		jwsAlgEdDSA: {},
		jwsAlgES256: {}, jwsAlgES384: {}, jwsAlgES512: {},
		jwsAlgRS256: {},
		jwsAlgPS256: {},
	}
}

// AsymmetricJWSAlgValues returns AsymmetricJWSAlgs as a deterministically
// sorted slice — for the discovery doc's *_signing_alg_values_supported
// lists (token_endpoint_auth / request_object / dpop), which MUST reflect
// the algs actually accepted on the wire rather than only what the server
// signs with.
func AsymmetricJWSAlgValues() []string {
	algs := AsymmetricJWSAlgs()
	out := make([]string, 0, len(algs))
	for a := range algs {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// hashForAlg maps an RSA/EC JWS alg onto its SHA-2 hash.
func hashForAlg(alg string) crypto.Hash {
	switch alg {
	case jwsAlgRS256, jwsAlgPS256, jwsAlgES256:
		return crypto.SHA256
	case jwsAlgRS384, jwsAlgPS384, jwsAlgES384:
		return crypto.SHA384
	case jwsAlgRS512, jwsAlgPS512, jwsAlgES512:
		return crypto.SHA512
	default:
		return 0
	}
}

// digestOf hashes the signing input with the SHA-2 size matching alg.
// EdDSA never reaches here (ed25519.Verify hashes internally).
func digestOf(alg string, message []byte) []byte {
	switch hashForAlg(alg) {
	case crypto.SHA256:
		d := sha256.Sum256(message)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(message)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(message)
		return d[:]
	default:
		return nil
	}
}
