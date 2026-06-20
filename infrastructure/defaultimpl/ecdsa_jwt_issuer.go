package defaultimpl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

// ECDSA / ES256 JWT constants.
const (
	jwtAlgES256 = "ES256"
	jwkKtyEC    = "EC"
	jwkCrvP256  = "P-256"

	// p256CoordinateBytes is the fixed octet length of each P-256
	// affine coordinate and of each ES256 signature scalar (R, S),
	// per RFC 7518 §3.4: "The integer R [and S] is converted to a
	// byte sequence of [ceil(log2(P)/8)] octets" — 32 for P-256.
	// JWS ES256 signatures are the fixed-width R||S concatenation
	// (64 bytes total), NOT the variable-length ASN.1 DER form that
	// crypto/ecdsa.SignASN1 emits.
	p256CoordinateBytes = 32
)

// supportedES256Algs is the ECDSA issuer's Validate-time alg allowlist.
// Per RFC 9068 §4 the recipient MUST reject any token whose header `alg`
// is outside the allowlist BEFORE the signature is verified. This issuer
// signs ES256 only, so EdDSA, RS256, `none`, and every symmetric alg are
// rejected up front — defeating algorithm-confusion attacks where an RP
// (or attacker) tries to dictate the verification algorithm independent
// of the key the kid actually names.
//
// The strict kid->alg correspondence is structural: an EdDSA token never
// reaches signature verification here because its `alg` fails this gate,
// and the EdDSA issuer rejects ES256 tokens symmetrically. In the
// Server's linear multi-issuer Validate path each issuer therefore only
// accepts tokens minted with its own key type.
var supportedES256Algs = map[string]struct{}{
	jwtAlgES256: {},
}

// ECDSASigner abstracts the raw ECDSA signing operation so the
// process-held private key can be swapped for a KMS/HSM-backed signer
// without touching JWT assembly. Sign receives the JWS signing input
// (the "header.payload" bytes) and MUST return the fixed-width 64-byte
// R||S signature (RFC 7518 §3.4), NOT ASN.1 DER. Returning an error
// (e.g. a KMS round-trip failure) fails token issuance closed rather
// than emitting an unsigned token.
type ECDSASigner interface {
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

// softwareECDSASigner is the default in-process signer over a P-256 key.
type softwareECDSASigner struct{ priv *ecdsa.PrivateKey }

func (s softwareECDSASigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		return nil, err
	}
	return ecdsaJWSSignature(r, ss), nil
}

// ecdsaJWSSignature encodes (r, s) as the fixed-width R||S byte sequence
// JWS ES256 mandates (RFC 7518 §3.4): each scalar left-padded with zero
// octets to exactly 32 bytes.
func ecdsaJWSSignature(r, s *big.Int) []byte {
	out := make([]byte, 2*p256CoordinateBytes)
	r.FillBytes(out[:p256CoordinateBytes])
	s.FillBytes(out[p256CoordinateBytes:])
	return out
}

// ECDSAJWTIssuer signs 3-segment JWTs with an ECDSA P-256 key (ES256).
// It mirrors Ed25519JWTIssuer's interface set so an operator can swap the
// signing algorithm without touching any other wiring; the public key is
// published via JWKS (kty:"EC", crv:"P-256", x/y) so downstream gateways
// verify locally. RFC 9068 access-token claim rules are identical to the
// Ed25519 issuer (shared payload structs).
//
// Revocation is in-memory (deny set), like the Ed25519 issuer; persistent
// or distributed revocation requires a Redis/DB-backed replacement.
type ECDSAJWTIssuer struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	keyID      string
	issuer     string
	tokenTTL   time.Duration

	// maxClockSkew widens inbound exp/nbf checks per RFC 7519 §4.1.4-5.
	maxClockSkew time.Duration

	// verifyKeys maps kid -> public key for verify-only keys (the
	// retired half of a rotation). The primary key is registered here
	// too so Validate has one lookup path.
	verifyKeys map[string]*ecdsa.PublicKey

	// revoked is the exp-bounded revocation deny-set (full token -> `exp` in
	// unix seconds); see the Ed25519 issuer + revocation_set.go.
	revokedMu sync.RWMutex
	revoked   map[string]int64
	// revocationStore is the OPTIONAL durable backing for `revoked` (nil =
	// in-process only); Revoke persists, SeedRevocations re-seeds at boot.
	revocationStore RevocationStore

	// keyMu guards the active signing key + verifyKeys for runtime
	// rotation, matching the Ed25519 issuer's locking discipline.
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
	peerVerifyKeys map[string]*ecdsa.PublicKey

	// signer performs the raw ECDSA signing. Defaults to the in-process
	// software signer; WithECDSAExternalSigner swaps in a KMS/HSM signer.
	signer ECDSASigner
}

// ECDSAOption configures the issuer at construction time.
type ECDSAOption func(*ECDSAJWTIssuer)

func WithECDSAIssuer(name string) ECDSAOption {
	return func(j *ECDSAJWTIssuer) { j.issuer = name }
}

func WithECDSATokenTTL(ttl time.Duration) ECDSAOption {
	return func(j *ECDSAJWTIssuer) { j.tokenTTL = ttl }
}

// WithECDSAMaxClockSkew widens the inbound exp/nbf validation window per
// RFC 7519 §4.1.4-5. Mirrors WithEd25519MaxClockSkew.
func WithECDSAMaxClockSkew(skew time.Duration) ECDSAOption {
	return func(j *ECDSAJWTIssuer) {
		if skew > 0 {
			j.maxClockSkew = skew
		}
	}
}

// WithECDSAKey uses the supplied P-256 keypair instead of generating one.
// The key MUST be on the P-256 curve; NewECDSAJWTIssuer panics otherwise
// (a non-P-256 key would silently mint tokens no verifier can match).
func WithECDSAKey(priv *ecdsa.PrivateKey) ECDSAOption {
	return func(j *ECDSAJWTIssuer) {
		j.privateKey = priv
		if priv != nil {
			j.publicKey = &priv.PublicKey
		}
	}
}

// WithECDSAKeyID overrides the auto-derived kid.
func WithECDSAKeyID(kid string) ECDSAOption {
	return func(j *ECDSAJWTIssuer) { j.keyID = kid }
}

// WithECDSAVerifyKey adds a verify-only public key (the retired half of a
// rotation) so in-flight tokens stay verifiable through their TTL after a
// key swap. kid MUST be distinct from the primary and every other
// verify-only key. Idempotent.
func WithECDSAVerifyKey(kid string, pub *ecdsa.PublicKey) ECDSAOption {
	return func(j *ECDSAJWTIssuer) {
		if j.verifyKeys == nil {
			j.verifyKeys = make(map[string]*ecdsa.PublicKey, 2)
		}
		j.verifyKeys[kid] = pub
	}
}

// WithECDSAExternalSigner injects a signer whose private key lives outside
// this process (KMS/HSM). pub is the corresponding P-256 public key
// (published in JWKS, used by Validate); kid names it in token headers.
// The issuer never generates or holds a private key in this mode.
func WithECDSAExternalSigner(signer ECDSASigner, pub *ecdsa.PublicKey, kid string) ECDSAOption {
	return func(j *ECDSAJWTIssuer) {
		j.signer = signer
		j.publicKey = pub
		if kid != "" {
			j.keyID = kid
		}
	}
}

// NewECDSAJWTIssuer builds an ES256 issuer. With no key option it
// generates a fresh P-256 key. Panics on a non-P-256 supplied key or a
// key-generation failure (both are unrecoverable misconfigurations at
// startup, matching NewEd25519JWTIssuer's panic-on-generate-failure).
func NewECDSAJWTIssuer(opts ...ECDSAOption) *ECDSAJWTIssuer {
	j := &ECDSAJWTIssuer{
		issuer:   sso.DefaultIssuer,
		tokenTTL: defaultTokenTTL,
		revoked:  make(map[string]int64),
	}
	for _, opt := range opts {
		opt(j)
	}
	// Generate in-process only when neither a private key nor an
	// external signer was supplied.
	if j.privateKey == nil && j.signer == nil {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(fmt.Sprintf("ecdsa: generate key: %v", err))
		}
		j.privateKey = priv
		j.publicKey = &priv.PublicKey
	}
	if j.publicKey != nil && j.publicKey.Curve != elliptic.P256() {
		panic("ecdsa: ES256 issuer requires a P-256 key")
	}
	if j.signer == nil {
		j.signer = softwareECDSASigner{priv: j.privateKey}
	}
	if j.keyID == "" {
		j.keyID = ecdsaFingerprintKid(j.publicKey)
	}
	if j.verifyKeys == nil {
		j.verifyKeys = make(map[string]*ecdsa.PublicKey, 1)
	}
	j.verifyKeys[j.keyID] = j.publicKey
	// peerVerifyKeys starts empty: it only ever populates via AdoptVerifyKey
	// when this replica is wired into a shared signing-key registry. With no
	// registry it stays empty forever, so JWKS() and Validate() are
	// byte-identical to a build that lacks the aggregation feature.
	j.peerVerifyKeys = make(map[string]*ecdsa.PublicKey)
	return j
}

// AdoptVerifyKey installs a peer replica's ES256 signing public key as a
// VERIFY-ONLY key, so this replica's JWKS() serves it and Validate() accepts
// tokens it signed (package signingkeys). It NEVER affects signing — this
// replica keeps minting only with its own private key. Idempotent: re-adopting
// the same kid updates the public key in place.
//
// Defensive guards mirror the Ed25519 issuer: kid must be non-empty, pub must
// be a non-nil P-256 key (ES256's only curve — a key on another curve could
// never have signed an ES256 token this issuer accepts), and kid must NOT
// collide with this replica's active signing kid or any LOCAL verify key. A
// collision means two distinct keys claim one kid, breaking the O(1)
// kid->key lookup; it is rejected loudly rather than silently shadowing the
// local key.
func (j *ECDSAJWTIssuer) AdoptVerifyKey(kid string, pub *ecdsa.PublicKey) error {
	if kid == "" {
		return errors.New("ecdsa: adopt verify key: empty kid")
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return fmt.Errorf("ecdsa: adopt verify key %q: public key is not on P-256", kid)
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
		return fmt.Errorf("ecdsa: adopt verify key %q: kid collides with a local signing/verify key", kid)
	}

	j.peerKeysMu.Lock()
	defer j.peerKeysMu.Unlock()
	if j.peerVerifyKeys == nil {
		j.peerVerifyKeys = make(map[string]*ecdsa.PublicKey, 1)
	}
	j.peerVerifyKeys[kid] = pub
	return nil
}

// DropVerifyKey removes a previously adopted peer key (idempotent). It operates
// ONLY on peerVerifyKeys, never on local verifyKeys, so it can never strand a
// local signing/retired key — peer and local key lifecycles are independent.
func (j *ECDSAJWTIssuer) DropVerifyKey(kid string) {
	j.peerKeysMu.Lock()
	defer j.peerKeysMu.Unlock()
	delete(j.peerVerifyKeys, kid)
}

// currentKey snapshots the active signer + its kid together under the
// read lock so a token's header kid and its signature always come from
// the same key even if RotateKey fires mid-issuance.
func (j *ECDSAJWTIssuer) currentKey() (ECDSASigner, string) {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	return j.signer, j.keyID
}

// PublicKey returns the active verification key.
func (j *ECDSAJWTIssuer) PublicKey() *ecdsa.PublicKey {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	return j.publicKey
}

// KeyID returns the kid stamped in every issued token's header.
func (j *ECDSAJWTIssuer) KeyID() string {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	return j.keyID
}

// RotateKey promotes a new P-256 signing key, demoting the current one to
// verify-only so its in-flight tokens stay valid through their TTL. Pass
// nil to generate a fresh key. Returns the new kid. Safe for concurrent
// use. Rotates the in-process software signer only; external signers
// rotate via their own backend.
func (j *ECDSAJWTIssuer) RotateKey(priv *ecdsa.PrivateKey) (string, error) {
	if priv == nil {
		var err error
		if priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return "", fmt.Errorf("ecdsa: rotate generate key: %w", err)
		}
	}
	if priv.Curve != elliptic.P256() {
		return "", errors.New("ecdsa: rotate: key is not on P-256")
	}
	pub := &priv.PublicKey
	newKID := ecdsaFingerprintKid(pub)

	j.keyMu.Lock()
	defer j.keyMu.Unlock()
	if j.publicKey != nil && j.keyID != "" {
		if j.verifyKeys == nil {
			j.verifyKeys = make(map[string]*ecdsa.PublicKey, 2)
		}
		j.verifyKeys[j.keyID] = j.publicKey
	}
	j.privateKey = priv
	j.publicKey = pub
	j.keyID = newKID
	j.signer = softwareECDSASigner{priv: priv}
	j.verifyKeys[newKID] = pub
	return newKID, nil
}

// RetireKey drops a verify-only key from JWKS. Refuses to retire the
// active signing key.
func (j *ECDSAJWTIssuer) RetireKey(kid string) error {
	j.keyMu.Lock()
	defer j.keyMu.Unlock()
	if kid == j.keyID {
		return errors.New("ecdsa: cannot retire the active signing key")
	}
	delete(j.verifyKeys, kid)
	return nil
}

// ecdsaHeader is the JOSE header for ES256 JWTs.
type ecdsaHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}
