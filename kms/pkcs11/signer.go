package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
)

// ErrUnsupportedKey is returned when the token key (or the requested signing
// scheme) is not one this signer can bridge into the JWS issuers. Supported
// keys are EC (NIST P-256/384/521 -> ES256/384/512), RSA (2048+ ->
// RS256/PS256), and Ed25519 (-> EdDSA, only where the token implements
// CKM_EDDSA). Anything else is rejected here rather than silently mis-signed.
var ErrUnsupportedKey = errors.New("pkcs11: unsupported key type or signing scheme")

// Mechanism is the PKCS#11 signing mechanism this signer asks the [Session]
// to apply. It is a small package-local enum (NOT the miekg/pkcs11 CK_*
// constant) so signer.go — and the fake [Session] in tests — need not import
// the cgo binding; session.go maps it to the real pkcs11.CKM_* mechanism.
type Mechanism int

const (
	// MechECDSA is CKM_ECDSA: the token signs the precomputed digest and
	// returns the signature as RAW fixed-width R||S (PKCS#11 v2.40 §2.3.1),
	// which Sign converts to ASN.1 DER for the crypto.Signer contract.
	MechECDSA Mechanism = iota
	// MechRSAPKCS1v15 is CKM_RSA_PKCS: PKCS#1 v1.5 over the DER DigestInfo
	// of the digest. The caller supplies the DigestInfo-wrapped bytes.
	MechRSAPKCS1v15
	// MechRSAPSS is CKM_RSA_PKCS_PSS: RSASSA-PSS over the raw digest, with
	// the PSS params (SHA-256, MGF1-SHA-256, salt=hashlen) carried alongside.
	MechRSAPSS
	// MechEdDSA is CKM_EDDSA: Ed25519 over the RAW message (no pre-hash).
	MechEdDSA
)

func (m Mechanism) String() string {
	switch m {
	case MechECDSA:
		return "CKM_ECDSA"
	case MechRSAPKCS1v15:
		return "CKM_RSA_PKCS"
	case MechRSAPSS:
		return "CKM_RSA_PKCS_PSS"
	case MechEdDSA:
		return "CKM_EDDSA"
	default:
		return fmt.Sprintf("Mechanism(%d)", int(m))
	}
}

// Session is the minimal slice of PKCS#11 token operations [Signer] needs.
// Declaring our own interface (rather than depending on *pkcs11.Ctx +
// SessionHandle directly) keeps the seam test-injectable: the real
// miekg/pkcs11-backed implementation in session.go satisfies it, and
// signer_test.go injects an in-process fake — so the crypto logic is unit-
// tested with NO real HSM, NO SoftHSM, and NO cgo round-trip. Only the two
// operations actually used appear here, mirroring awskms.KMSAPI's philosophy.
//
// PKCS#11 sessions are NOT safe for concurrent C_Sign calls (one operation
// is in flight per session per the spec), so the real implementation
// serializes Sign internally; callers (the JWS issuers) may invoke
// [Signer.Sign] concurrently regardless.
type Session interface {
	// Sign performs the full SignInit+Sign sequence: it initializes mech
	// against the private-key object keyHandle, signs data, and returns the
	// token's raw signature (R||S for CKM_ECDSA, raw bytes for RSA/EdDSA).
	// For MechRSAPSS the PSS parameters are implied by the mechanism (the
	// real session attaches them); callers pass the bare digest. The token
	// owns all signing randomness.
	Sign(mech Mechanism, keyHandle uint, data []byte) ([]byte, error)

	// PublicKeyDER returns the public half of the signing key as a
	// DER-encoded SubjectPublicKeyInfo (RFC 5280), assembled from the token's
	// public-key object attributes (CKA_EC_POINT+CKA_EC_PARAMS for EC,
	// CKA_MODULUS+CKA_PUBLIC_EXPONENT for RSA, CKA_EC_POINT for Ed25519).
	// Returning SPKI (rather than raw attributes) lets Signer reuse
	// x509.ParsePKIXPublicKey, exactly as awskms parses KMS's GetPublicKey.
	PublicKeyDER() ([]byte, error)
}

// Signer is a [crypto.Signer] backed by a PKCS#11 token key. The private key
// never leaves the token — every Sign is a C_Sign round-trip into the HSM /
// smart card. The process holds only the public half (cached) and the
// private-key object handle.
//
// It is wired into the SSO issuers through the cryptosigner bridge, NOT
// directly:
//
//	sgn, err := pkcs11.New(cfg)                      // P-256 key
//	bridge, pub, err := cryptosigner.ECDSA(sgn)      // ES256
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(bridge, pub, cfg.KeyLabel),
//	)
//
// crypto.Signer contract:
//
//   - Public() returns the parsed public key (*ecdsa.PublicKey /
//     *rsa.PublicKey / ed25519.PublicKey), read from the token once and
//     cached.
//   - Sign(rand, digest, opts) signs. For EC/RSA, digest is the ALREADY-
//     hashed message and opts.HashFunc() names the hash (and *rsa.PSSOptions
//     selects PSS). For Ed25519, opts.HashFunc()==0 and digest is the raw
//     message (Ed25519's contract). The rand reader is ignored — the token
//     owns signing randomness.
//   - For ECDSA the returned signature is ASN.1 DER (SEQUENCE{r,s}). CKM_ECDSA
//     gives RAW R||S, so Sign converts R||S -> DER; the cryptosigner bridge
//     converts DER -> JWS R||S (RFC 7518 §3.4). The double conversion keeps
//     this type a faithful crypto.Signer (round-trips against ecdsa.VerifyASN1).
//   - For RSA the signature is raw PKCS#1 v1.5 / PSS bytes (already JWS form).
//   - For Ed25519 the signature is the raw 64-byte value (already JWS form).
//
// Fail-closed: any token error from Sign is returned, so token issuance fails
// rather than emitting an unsigned or partially-signed token.
type Signer struct {
	sess      Session
	keyHandle uint // CKO_PRIVATE_KEY object handle located at construction

	// mu guards the public-key cache. A token's public key is immutable for
	// a key object, so one successful read suffices for the process lifetime
	// and Public() (called on every wiring + JWKS build) stays cheap.
	//
	// We deliberately do NOT use sync.Once: Once's only retry path is
	// resetting the Once value, and writing a sync.Once while peers call .Do
	// on it is a data race (the detector flags it; a real issuer signs
	// concurrently). The mutex distinguishes not-yet-read, cached-success
	// (loaded==true, immutable once set), and transient-error (loaded stays
	// false -> the NEXT call retries, so a startup token outage is not
	// permanently poisoned). Mirrors awskms.Signer exactly.
	mu     sync.Mutex
	cached crypto.PublicKey
	loaded bool

	// suppliedPub, when non-nil, short-circuits the token public-key read:
	// the operator passed the public half at construction (e.g. from a
	// certificate), so Public() never touches the token. Still served through
	// the mu-guarded cache for a uniform code path.
	suppliedPub crypto.PublicKey
}

// NewSigner builds a Signer over an already-opened [Session] and the located
// private-key object handle. It does NOT touch the token — the first Public()
// or Sign() performs the lazy public-key read. The production [New]
// constructor (session.go) wires a real miekg/pkcs11 session; tests inject a
// fake. suppliedPub MAY be nil (read the public key from the token) or the
// known public half (skip the read).
func NewSigner(sess Session, keyHandle uint, suppliedPub crypto.PublicKey) (*Signer, error) {
	if sess == nil {
		return nil, errors.New("pkcs11: nil session")
	}
	return &Signer{sess: sess, keyHandle: keyHandle, suppliedPub: suppliedPub}, nil
}

// loadPublic reads + parses the public key once, caching success for the
// process lifetime. The token returns SPKI DER (assembled by the Session from
// the public-key object's attributes), which x509.ParsePKIXPublicKey turns
// into a *ecdsa.PublicKey / *rsa.PublicKey / ed25519.PublicKey.
//
// The mutex (not sync.Once) lets a transient token error be retried on the
// next call without a Once-reset data race. Success is cached immutably; an
// error returns WITHOUT setting loaded, so the next caller re-attempts.
func (s *Signer) loadPublic() (crypto.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded {
		return s.cached, nil
	}
	if s.suppliedPub != nil {
		if err := assertSupportedPublic(s.suppliedPub); err != nil {
			return nil, err
		}
		s.cached = s.suppliedPub
		s.loaded = true
		return s.cached, nil
	}
	der, err := s.sess.PublicKeyDER()
	if err != nil {
		// Transient (token busy / disconnected): NOT cached — retried next call.
		return nil, fmt.Errorf("pkcs11: read public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse public key DER: %w", err)
	}
	if err := assertSupportedPublic(pub); err != nil {
		return nil, err
	}
	s.cached = pub
	s.loaded = true
	return s.cached, nil
}

// assertSupportedPublic rejects key types this signer cannot bridge before
// they are cached, so a misconfigured token fails loud rather than at the
// first Sign.
func assertSupportedPublic(pub crypto.PublicKey) error {
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("pkcs11: %w: public key type %T", ErrUnsupportedKey, pub)
	}
}

// Public implements crypto.Signer. It returns the parsed public key, reading
// + caching it from the token on first call. On a token or parse error it
// returns nil (crypto.Signer has no error return here); the subsequent Sign —
// or the cryptosigner bridge's wiring-time shape check — surfaces the failure.
// Use PublicKey() for an explicit startup error.
func (s *Signer) Public() crypto.PublicKey {
	pub, err := s.loadPublic()
	if err != nil {
		return nil
	}
	return pub
}

// PublicKey is the error-returning form of Public, for wiring-time use
// (operators SHOULD call it once at startup so a misconfigured key
// label/PIN/permission fails loud before the first token issuance).
func (s *Signer) PublicKey() (crypto.PublicKey, error) {
	return s.loadPublic()
}

// Sign implements crypto.Signer over a token key. For EC/RSA, digest is the
// ALREADY-computed message digest (crypto.Signer's contract) and
// opts.HashFunc() names the hash (and, when opts is *rsa.PSSOptions, selects
// PSS). For Ed25519, opts.HashFunc()==0 and digest is the raw message. The
// rand reader is ignored — the token owns signing randomness.
//
// It selects the (key type, hash, padding) -> PKCS#11 mechanism, performs the
// C_SignInit+C_Sign via the Session, and returns: ASN.1 DER for ECDSA (the
// stdlib ECDSA crypto.Signer contract — converted here from the token's raw
// R||S; the cryptosigner bridge re-converts to JWS R||S), raw bytes for RSA
// and Ed25519.
//
// Cancellation: crypto.Signer.Sign carries no context (the stdlib contract).
// A networked HSM that hangs is bounded by whatever timeout the underlying
// PKCS#11 module / transport enforces — the miekg/pkcs11 C_Sign call itself
// is blocking and not context-aware, so operators relying on a flaky remote
// token SHOULD configure the token's own connection timeout. (Local PCIe/USB
// tokens do not hang.)
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		// crypto.SignerOpts MAY be nil per the contract, but this signer
		// needs the hash (and PSS selection) it carries; guard before any
		// opts use so a nil never panics on opts.HashFunc() below.
		return nil, fmt.Errorf("pkcs11: %w: nil SignerOpts", ErrUnsupportedKey)
	}

	pub, err := s.loadPublic()
	if err != nil {
		return nil, err
	}

	switch pk := pub.(type) {
	case *ecdsa.PublicKey:
		// The curve fixes the JWS hash (P-256->SHA-256, P-384->SHA-384,
		// P-521->SHA-512). Reject any other pairing fail-closed -- matching
		// the awskms/gcpkms peers -- so a direct crypto.Signer caller cannot
		// sign a digest that would verify under a different hash than the
		// ES* alg the JWKS publishes. (The issuer/cryptosigner bridge always
		// pairs them; this guards the public crypto.Signer contract. The
		// !=want check also subsumes the HashFunc()==0 rejection.)
		want, ok := ecdsaHashForCurve(pk.Curve)
		if !ok {
			return nil, fmt.Errorf("pkcs11: %w: unsupported ECDSA curve %s", ErrUnsupportedKey, pk.Curve.Params().Name)
		}
		if opts.HashFunc() != want {
			return nil, fmt.Errorf("pkcs11: %w: %s key requires %v, got %v", ErrUnsupportedKey, pk.Curve.Params().Name, want, opts.HashFunc())
		}
		raw, err := s.sess.Sign(MechECDSA, s.keyHandle, digest)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: ecdsa sign: %w", err)
		}
		// CKM_ECDSA returns RAW R||S; the crypto.Signer ECDSA contract is DER.
		der, err := rawECDSAToDER(raw, pk.Curve)
		if err != nil {
			return nil, err
		}
		return der, nil

	case *rsa.PublicKey:
		if opts.HashFunc() != crypto.SHA256 {
			return nil, fmt.Errorf("pkcs11: %w: RSA with hash %v (only SHA-256 / RS256|PS256 supported)", ErrUnsupportedKey, opts.HashFunc())
		}
		if _, pss := opts.(*rsa.PSSOptions); pss {
			sig, err := s.sess.Sign(MechRSAPSS, s.keyHandle, digest)
			if err != nil {
				return nil, fmt.Errorf("pkcs11: rsa-pss sign: %w", err)
			}
			return sig, nil
		}
		// RS256: CKM_RSA_PKCS signs the DER DigestInfo, not the bare digest.
		// Wrap the digest so the token produces a standards-compliant
		// PKCS#1 v1.5 signature any verifier (and go-jose) accepts.
		di, err := digestInfoSHA256(digest)
		if err != nil {
			return nil, err
		}
		sig, err := s.sess.Sign(MechRSAPKCS1v15, s.keyHandle, di)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: rsa-pkcs1v15 sign: %w", err)
		}
		return sig, nil

	case ed25519.PublicKey:
		if opts.HashFunc() != crypto.Hash(0) {
			// Ed25519ph (pre-hashed) is not what go-jose EdDSA uses; the JWS
			// EdDSA issuer signs the raw message (HashFunc()==0).
			return nil, fmt.Errorf("pkcs11: %w: Ed25519 requires opts.HashFunc()==0 (raw message), got %v", ErrUnsupportedKey, opts.HashFunc())
		}
		sig, err := s.sess.Sign(MechEdDSA, s.keyHandle, digest)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: eddsa sign: %w", err)
		}
		if len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("pkcs11: EdDSA signature length %d, want %d", len(sig), ed25519.SignatureSize)
		}
		return sig, nil

	default:
		return nil, fmt.Errorf("pkcs11: %w: public key type %T", ErrUnsupportedKey, pub)
	}
}

// ecdsaDERSignature is the ASN.1 SEQUENCE { r INTEGER, s INTEGER } the stdlib
// crypto.Signer ECDSA contract mandates (and ecdsa.VerifyASN1 consumes).
type ecdsaDERSignature struct{ R, S *big.Int }

// rawECDSAToDER converts the token's raw fixed-width R||S (what CKM_ECDSA
// returns, PKCS#11 v2.40 §2.3.1) into the ASN.1 DER form the crypto.Signer
// ECDSA contract requires. The raw signature is exactly 2*ceil(bits/8) bytes —
// R then S, each left-padded to the curve's coordinate octet length — so we
// split it in half and DER-encode the two integers. It rejects a length that
// does not match the curve rather than emit a signature no verifier accepts.
// ecdsaHashForCurve returns the JWS-paired hash for an EC curve: P-256->
// SHA-256 (ES256), P-384->SHA-384 (ES384), P-521->SHA-512 (ES512). The curve
// fixes the hash, so Sign rejects any other pairing (matching awskms/gcpkms).
func ecdsaHashForCurve(c elliptic.Curve) (crypto.Hash, bool) {
	switch c {
	case elliptic.P256():
		return crypto.SHA256, true
	case elliptic.P384():
		return crypto.SHA384, true
	case elliptic.P521():
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func rawECDSAToDER(raw []byte, curve elliptic.Curve) ([]byte, error) {
	coordLen := (curve.Params().BitSize + 7) / 8
	if len(raw) != 2*coordLen {
		return nil, fmt.Errorf("pkcs11: raw ECDSA signature length %d, want %d (2*%d for %s)",
			len(raw), 2*coordLen, coordLen, curve.Params().Name)
	}
	r := new(big.Int).SetBytes(raw[:coordLen])
	sv := new(big.Int).SetBytes(raw[coordLen:])
	if r.Sign() <= 0 || sv.Sign() <= 0 {
		return nil, errors.New("pkcs11: token returned non-positive R or S")
	}
	der, err := asn1.Marshal(ecdsaDERSignature{R: r, S: sv})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: marshal ECDSA DER: %w", err)
	}
	return der, nil
}

// sha256DigestInfoPrefix is the fixed DER prefix of a PKCS#1 v1.5 DigestInfo
// for SHA-256 (RFC 8017 §9.2 / Notes): the AlgorithmIdentifier SEQUENCE for
// id-sha256 followed by the OCTET STRING tag+length of a 32-byte hash. The
// digest is appended to form the full DigestInfo that CKM_RSA_PKCS signs.
var sha256DigestInfoPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20,
}

// digestInfoSHA256 wraps a 32-byte SHA-256 digest in the PKCS#1 v1.5
// DigestInfo so CKM_RSA_PKCS (which expects DigestInfo, not a bare digest)
// yields a standards-compliant RS256 signature.
func digestInfoSHA256(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("pkcs11: %w: SHA-256 digest length %d, want 32", ErrUnsupportedKey, len(digest))
	}
	out := make([]byte, 0, len(sha256DigestInfoPrefix)+len(digest))
	out = append(out, sha256DigestInfoPrefix...)
	out = append(out, digest...)
	return out, nil
}

// Interface guard: Signer is a stdlib crypto.Signer, the exact seam the
// cryptosigner bridge (and any other crypto.Signer consumer) accepts.
var _ crypto.Signer = (*Signer)(nil)
