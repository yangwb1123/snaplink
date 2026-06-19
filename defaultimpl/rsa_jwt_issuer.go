package defaultimpl

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/snaplink/sso"
)

// RSA JWT constants.
const (
	jwtAlgRS256 = "RS256" // RSASSA-PKCS1-v1_5 + SHA-256
	jwtAlgPS256 = "PS256" // RSASSA-PSS + SHA-256 (FAPI-preferred)
	jwkKtyRSA   = "RSA"

	// rsaMinKeyBits is the smallest modulus this issuer will sign with
	// (RFC 7518 §3.3 requires >= 2048). A smaller key is a
	// non-recoverable startup misconfiguration (panic), matching the
	// ECDSA issuer's P-256-only guard.
	rsaMinKeyBits = 2048
)

// RSASigner abstracts the raw RSA signing operation so the process-held
// private key can be swapped for a KMS/HSM-backed signer without touching
// JWT assembly. Sign receives the JWS signing input ("header.payload")
// and MUST return the raw signature bytes for the issuer's configured alg
// (RS256 → PKCS1v15, PS256 → PSS), both over SHA-256. Returning an error
// fails issuance closed rather than emitting an unsigned token.
type RSASigner interface {
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

// softwareRSASigner is the default in-process signer. alg selects the
// padding scheme (RS256 vs PS256).
type softwareRSASigner struct {
	priv *rsa.PrivateKey
	alg  string
}

func (s softwareRSASigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	if s.alg == jwtAlgPS256 {
		return rsa.SignPSS(rand.Reader, s.priv, crypto.SHA256, digest[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
	}
	return rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, digest[:])
}

// RSAJWTIssuer signs 3-segment JWTs with an RSA key (RS256 or PS256). It
// mirrors Ed25519JWTIssuer / ECDSAJWTIssuer's interface set so an operator
// can swap the signing algorithm without touching any other wiring; the
// public key is published via JWKS (kty:"RSA", n/e) so downstream gateways
// verify locally. RFC 9068 access-token claim rules are identical across
// signers (shared payload structs).
//
// Revocation is in-memory (deny set), like the other issuers; persistent
// or distributed revocation requires a Redis/DB-backed replacement.
type RSAJWTIssuer struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	issuer     string
	tokenTTL   time.Duration
	alg        string // RS256 | PS256 — the only alg this issuer signs + accepts

	// maxClockSkew widens inbound exp/nbf checks per RFC 7519 §4.1.4-5.
	maxClockSkew time.Duration

	// verifyKeys maps kid -> public key for verify-only keys (the retired
	// half of a rotation). The primary is registered here too so Validate
	// has one lookup path.
	verifyKeys map[string]*rsa.PublicKey

	// revoked is the exp-bounded revocation deny-set (full token -> `exp` in
	// unix seconds); see the Ed25519 issuer + revocation_set.go.
	revokedMu sync.RWMutex
	revoked   map[string]int64
	// revocationStore is the OPTIONAL durable backing for `revoked` (nil =
	// in-process only); Revoke persists, SeedRevocations re-seeds at boot.
	revocationStore RevocationStore

	// keyMu guards the active signing key + verifyKeys for runtime
	// rotation, matching the other issuers' locking discipline.
	keyMu sync.RWMutex

	// peerVerifyKeys holds VERIFY-ONLY public keys adopted from OTHER
	// replicas in a leaderless multi-replica deployment (package
	// signingkeys). It is deliberately SEPARATE from verifyKeys, guarded by
	// its own mutex, so this replica's local key lifecycle — RotateKey /
	// RetireKey — NEVER touches peer keys: peer-key lifecycle is owned by
	// the registry/peer side, not by local rotation. The two mutexes are
	// never held nested; lock order is independent (acquire one, fully
	// release, then acquire the other) — see lookupVerifyKey and JWKS.
	peerKeysMu     sync.RWMutex
	peerVerifyKeys map[string]*rsa.PublicKey

	// signer performs the raw RSA signing. Defaults to the in-process
	// software signer; WithRSAExternalSigner swaps in a KMS/HSM signer.
	signer RSASigner
}

// RSAOption configures the issuer at construction time.
type RSAOption func(*RSAJWTIssuer)

func WithRSAIssuer(name string) RSAOption {
	return func(j *RSAJWTIssuer) { j.issuer = name }
}

func WithRSATokenTTL(ttl time.Duration) RSAOption {
	return func(j *RSAJWTIssuer) { j.tokenTTL = ttl }
}

// WithRSAAlg selects RS256 (default) or PS256. Any other value panics at
// construction (an unsupported alg would mint tokens no verifier matches).
func WithRSAAlg(alg string) RSAOption {
	return func(j *RSAJWTIssuer) { j.alg = alg }
}

// WithRSAMaxClockSkew widens the inbound exp/nbf validation window per
// RFC 7519 §4.1.4-5.
func WithRSAMaxClockSkew(skew time.Duration) RSAOption {
	return func(j *RSAJWTIssuer) {
		if skew > 0 {
			j.maxClockSkew = skew
		}
	}
}

// WithRSAKey uses the supplied keypair instead of generating one. The key
// MUST be >= 2048 bits; NewRSAJWTIssuer panics otherwise.
func WithRSAKey(priv *rsa.PrivateKey) RSAOption {
	return func(j *RSAJWTIssuer) {
		j.privateKey = priv
		if priv != nil {
			j.publicKey = &priv.PublicKey
		}
	}
}

// WithRSAKeyID overrides the auto-derived kid.
func WithRSAKeyID(kid string) RSAOption {
	return func(j *RSAJWTIssuer) { j.keyID = kid }
}

// WithRSAVerifyKey adds a verify-only public key (the retired half of a
// rotation) so in-flight tokens stay verifiable through their TTL after a
// key swap. kid MUST be distinct from the primary. Idempotent.
func WithRSAVerifyKey(kid string, pub *rsa.PublicKey) RSAOption {
	return func(j *RSAJWTIssuer) {
		if j.verifyKeys == nil {
			j.verifyKeys = make(map[string]*rsa.PublicKey, 2)
		}
		j.verifyKeys[kid] = pub
	}
}

// WithRSAExternalSigner injects a signer whose private key lives outside
// this process (KMS/HSM). pub is the corresponding RSA public key
// (published in JWKS, used by Validate); kid names it in token headers.
// The signer MUST sign for the issuer's configured alg (set WithRSAAlg to
// match). The issuer never holds a private key in this mode.
func WithRSAExternalSigner(signer RSASigner, pub *rsa.PublicKey, kid string) RSAOption {
	return func(j *RSAJWTIssuer) {
		j.signer = signer
		j.publicKey = pub
		if kid != "" {
			j.keyID = kid
		}
	}
}

// NewRSAJWTIssuer builds an RS256/PS256 issuer. With no key option it
// generates a fresh 2048-bit key. Panics on an unsupported alg, a
// sub-2048-bit supplied key, or a key-generation failure (all
// unrecoverable startup misconfigurations).
func NewRSAJWTIssuer(opts ...RSAOption) *RSAJWTIssuer {
	j := &RSAJWTIssuer{
		issuer:   sso.DefaultIssuer,
		tokenTTL: defaultTokenTTL,
		alg:      jwtAlgRS256,
		revoked:  make(map[string]int64),
	}
	for _, opt := range opts {
		opt(j)
	}
	if j.alg != jwtAlgRS256 && j.alg != jwtAlgPS256 {
		panic(fmt.Sprintf("rsa: unsupported alg %q (want RS256 or PS256)", j.alg))
	}
	// Generate in-process only when neither a private key nor an external
	// signer was supplied.
	if j.privateKey == nil && j.signer == nil {
		priv, err := rsa.GenerateKey(rand.Reader, rsaMinKeyBits)
		if err != nil {
			panic(fmt.Sprintf("rsa: generate key: %v", err))
		}
		j.privateKey = priv
		j.publicKey = &priv.PublicKey
	}
	if j.publicKey != nil && j.publicKey.N.BitLen() < rsaMinKeyBits {
		panic(fmt.Sprintf("rsa: key is %d bits, minimum is %d", j.publicKey.N.BitLen(), rsaMinKeyBits))
	}
	if j.signer == nil {
		j.signer = softwareRSASigner{priv: j.privateKey, alg: j.alg}
	}
	if j.keyID == "" {
		j.keyID = rsaFingerprintKid(j.publicKey)
	}
	if j.verifyKeys == nil {
		j.verifyKeys = make(map[string]*rsa.PublicKey, 1)
	}
	j.verifyKeys[j.keyID] = j.publicKey
	// peerVerifyKeys starts empty: it only ever populates via AdoptVerifyKey
	// when this replica is wired into a shared signing-key registry. With no
	// registry it stays empty forever, so JWKS() and Validate() are
	// byte-identical to a build that lacks the aggregation feature.
	j.peerVerifyKeys = make(map[string]*rsa.PublicKey)
	return j
}

// AdoptVerifyKey installs a peer replica's RSA signing public key as a
// VERIFY-ONLY key, so this replica's JWKS() serves it and Validate() accepts
// tokens it signed (package signingkeys). It NEVER affects signing — this
// replica keeps minting only with its own private key. Idempotent: re-adopting
// the same kid updates the public key in place.
//
// Defensive guards mirror the other issuers: kid must be non-empty; pub must be
// non-nil and meet the SAME modulus floor this issuer enforces on its own keys
// (rsaMinKeyBits, RFC 7518 §3.3 >= 2048) — a sub-floor peer key is rejected so
// a weak key never enters this replica's verify-set via aggregation; and kid
// must NOT collide with this replica's active signing kid or any LOCAL verify
// key. A collision means two distinct keys claim one kid, breaking the O(1)
// kid->key lookup; it is rejected loudly rather than silently shadowing the
// local key.
//
// Alg-strictness (RS256 vs PS256) is enforced by the Server's alg-match gate
// BEFORE this call (a PS256-announced key never reaches an RS256 issuer and
// vice versa), so the padding scheme need not be re-checked here; the key
// material itself is identical across the two paddings.
func (j *RSAJWTIssuer) AdoptVerifyKey(kid string, pub *rsa.PublicKey) error {
	if kid == "" {
		return errors.New("rsa: adopt verify key: empty kid")
	}
	if pub == nil || pub.N == nil {
		return fmt.Errorf("rsa: adopt verify key %q: nil public key", kid)
	}
	if pub.N.BitLen() < rsaMinKeyBits {
		return fmt.Errorf("rsa: adopt verify key %q: key is %d bits, minimum is %d", kid, pub.N.BitLen(), rsaMinKeyBits)
	}
	// Reject a degenerate public exponent defensively (decodeRSAJWK already
	// gates the registry path; this guards direct SDK callers). e=1 makes
	// verification the identity (universal forgery); even e is non-invertible
	// modulo the totient. Neither is rejected by Go's rsa.Verify*.
	if pub.E < 3 || pub.E&1 == 0 {
		return fmt.Errorf("rsa: adopt verify key %q: degenerate public exponent %d", kid, pub.E)
	}
	// Read local key identity under keyMu, then release it fully before
	// touching peerKeysMu — the two locks are never held nested.
	j.keyMu.RLock()
	collidesLocal := kid == j.keyID
	if !collidesLocal {
		_, collidesLocal = j.verifyKeys[kid]
	}
	j.keyMu.RUnlock()
	if collidesLocal {
		return fmt.Errorf("rsa: adopt verify key %q: kid collides with a local signing/verify key", kid)
	}

	j.peerKeysMu.Lock()
	defer j.peerKeysMu.Unlock()
	if j.peerVerifyKeys == nil {
		j.peerVerifyKeys = make(map[string]*rsa.PublicKey, 1)
	}
	j.peerVerifyKeys[kid] = pub
	return nil
}

// DropVerifyKey removes a previously adopted peer key (idempotent). It operates
// ONLY on peerVerifyKeys, never on local verifyKeys, so it can never strand a
// local signing/retired key — peer and local key lifecycles are independent.
func (j *RSAJWTIssuer) DropVerifyKey(kid string) {
	j.peerKeysMu.Lock()
	defer j.peerKeysMu.Unlock()
	delete(j.peerVerifyKeys, kid)
}

// currentKey snapshots the active signer + its kid together under the read
// lock so a token's header kid and its signature always come from the same
// key even if RotateKey fires mid-issuance.
func (j *RSAJWTIssuer) currentKey() (RSASigner, string) {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	return j.signer, j.keyID
}

// PublicKey returns the active verification key.
func (j *RSAJWTIssuer) PublicKey() *rsa.PublicKey {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	return j.publicKey
}

// KeyID returns the kid stamped in every issued token's header.
func (j *RSAJWTIssuer) KeyID() string {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	return j.keyID
}

// RotateKey promotes a new signing key, demoting the current one to
// verify-only so its in-flight tokens stay valid through their TTL. Pass
// nil to generate a fresh 2048-bit key. Returns the new kid. Safe for
// concurrent use. Rotates the in-process software signer only.
func (j *RSAJWTIssuer) RotateKey(priv *rsa.PrivateKey) (string, error) {
	if priv == nil {
		var err error
		if priv, err = rsa.GenerateKey(rand.Reader, rsaMinKeyBits); err != nil {
			return "", fmt.Errorf("rsa: rotate generate key: %w", err)
		}
	}
	if priv.N.BitLen() < rsaMinKeyBits {
		return "", fmt.Errorf("rsa: rotate: key is %d bits, minimum is %d", priv.N.BitLen(), rsaMinKeyBits)
	}
	pub := &priv.PublicKey
	newKID := rsaFingerprintKid(pub)

	j.keyMu.Lock()
	defer j.keyMu.Unlock()
	if j.publicKey != nil && j.keyID != "" {
		if j.verifyKeys == nil {
			j.verifyKeys = make(map[string]*rsa.PublicKey, 2)
		}
		j.verifyKeys[j.keyID] = j.publicKey
	}
	j.privateKey = priv
	j.publicKey = pub
	j.keyID = newKID
	j.signer = softwareRSASigner{priv: priv, alg: j.alg}
	j.verifyKeys[newKID] = pub
	return newKID, nil
}

// RetireKey drops a verify-only key from JWKS. Refuses the active key.
func (j *RSAJWTIssuer) RetireKey(kid string) error {
	j.keyMu.Lock()
	defer j.keyMu.Unlock()
	if kid == j.keyID {
		return errors.New("rsa: cannot retire the active signing key")
	}
	delete(j.verifyKeys, kid)
	return nil
}

// rsaHeader is the JOSE header for RSA JWTs.
type rsaHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}
