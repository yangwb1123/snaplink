package defaultimpl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/oidc"
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

	revokedMu sync.RWMutex
	revoked   map[string]struct{}

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
		revoked:  make(map[string]struct{}),
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

func (j *ECDSAJWTIssuer) Issue(ctx context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	sgn, kid := j.currentKey()
	if subject == nil || subject.ID == "" {
		return nil, errors.New("ecdsa: subject required")
	}
	now := time.Now()
	// Per-issuance TTL override (Client.AccessTokenTTL via Subject.TTL)
	// wins over the issuer default. Matches the Ed25519 issuer.
	effectiveTTL := j.tokenTTL
	if subject.TTL > 0 {
		effectiveTTL = subject.TTL
	}
	expiresAt := now.Add(effectiveTTL)

	// RFC 9068 §2.1: header typ MUST be at+jwt for access tokens.
	header := ecdsaHeader{Alg: jwtAlgES256, Typ: jwtTypAT, Kid: kid}

	// RFC 9068 §2.2 REQUIRES jti.
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("ecdsa: generate jti: %w", err)
	}

	// Reuse the Ed25519 issuer's payload shape — the JSON claim set is
	// algorithm-independent, so RFC 9068 §2.2 claim handling stays
	// byte-for-byte identical across signers.
	payload := ed25519Payload{
		Iss:      j.issuer,
		Sub:      subject.ID,
		Exp:      expiresAt.Unix(),
		Nbf:      now.Unix(),
		Iat:      now.Unix(),
		Scope:    strings.Join(scopes, " "),
		Extra:    subject.Claims,
		ClientID: subject.ClientID,
		JTI:      jti,
		ACR:      subject.ACR,
		SID:      subject.SID,
	}
	if subject.ConfirmationJKT != "" || subject.ConfirmationX5TS256 != "" {
		payload.CNF = &confirmationClaim{
			JKT:     subject.ConfirmationJKT,
			X5TS256: subject.ConfirmationX5TS256,
		}
	}
	if !subject.AuthTime.IsZero() {
		payload.AuthTime = subject.AuthTime.Unix()
	}
	if len(subject.AMR) > 0 {
		payload.AMR = append([]string(nil), subject.AMR...)
	}
	if len(subject.AuthorizationDetails) > 0 {
		payload.AuthorizationDetails = append(json.RawMessage(nil), subject.AuthorizationDetails...)
	}
	if chain := actorChainToWire(subject.Actor); chain != nil {
		payload.Act = chain
	}
	if len(subject.Resources) > 0 {
		payload.Aud = audClaim(append([]string(nil), subject.Resources...))
	}

	signingInput, err := ecdsaSigningInput(header, payload)
	if err != nil {
		return nil, err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: sign access token: %w", err)
	}
	token := string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig)

	return &sso.Token{
		AccessToken: token,
		TokenType:   sso.TokenTypeBearer,
		ExpiresIn:   int(effectiveTTL.Seconds()),
		Scope:       payload.Scope,
		CreatedAt:   now,
	}, nil
}

func (j *ECDSAJWTIssuer) Validate(_ context.Context, token string) (*sso.TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("ecdsa: malformed token")
	}

	j.revokedMu.RLock()
	_, revoked := j.revoked[token]
	j.revokedMu.RUnlock()
	if revoked {
		return nil, errors.New("ecdsa: token revoked")
	}

	// RFC 9068 §4: enforce the alg + typ allowlists BEFORE signature
	// verification. An EdDSA / RS256 / `none` token fails here, never
	// reaching the ECDSA verify path — the structural guarantee that an
	// RP can't pick the verification algorithm.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("ecdsa: header decode: %w", err)
	}
	var h ecdsaHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("ecdsa: header parse: %w", err)
	}
	if _, ok := supportedES256Algs[h.Alg]; !ok {
		return nil, fmt.Errorf("ecdsa: alg %q not in allowlist", h.Alg)
	}
	if h.Typ != "" {
		if _, ok := supportedJWTTypes[h.Typ]; !ok {
			return nil, fmt.Errorf("ecdsa: typ %q not in allowlist", h.Typ)
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("ecdsa: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]

	pub := j.lookupVerifyKey(h.Kid)
	if pub == nil {
		return nil, errors.New("ecdsa: unknown kid")
	}
	if !ecdsaVerifyJWS(pub, []byte(signingInput), sig) {
		return nil, errors.New("ecdsa: signature invalid")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ecdsa: payload decode: %w", err)
	}
	var p ed25519Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("ecdsa: payload parse: %w", err)
	}

	now := time.Now().Unix()
	skew := int64(j.maxClockSkew.Seconds())
	if p.Exp != 0 && now-skew >= p.Exp {
		return nil, errors.New("ecdsa: token expired")
	}
	if p.Nbf != 0 && now+skew < p.Nbf {
		return nil, errors.New("ecdsa: token not yet valid")
	}

	claims := &sso.TokenClaims{
		Subject:   p.Sub,
		Issuer:    p.Iss,
		Audience:  []string(p.Aud),
		ExpiresAt: time.Unix(p.Exp, 0),
		NotBefore: time.Unix(p.Nbf, 0),
		IssuedAt:  time.Unix(p.Iat, 0),
		Extra:     p.Extra,
		ClientID:  p.ClientID,
		JTI:       p.JTI,
		ACR:       p.ACR,
		AMR:       append([]string(nil), p.AMR...),
		SID:       p.SID,
	}
	if p.CNF != nil {
		claims.ConfirmationJKT = p.CNF.JKT
		claims.ConfirmationX5TS256 = p.CNF.X5TS256
	}
	if len(p.AuthorizationDetails) > 0 {
		claims.AuthorizationDetails = append(json.RawMessage(nil), p.AuthorizationDetails...)
	}
	if p.AuthTime > 0 {
		claims.AuthTime = time.Unix(p.AuthTime, 0)
	}
	if p.Scope != "" {
		claims.Scopes = strings.Split(p.Scope, " ")
	}
	if chain := wireChainToActor(p.Act); chain != nil {
		claims.Actor = chain
	}
	return claims, nil
}

// ecdsaVerifyJWS verifies a fixed-width R||S ES256 signature (RFC 7518
// §3.4). Rejects any signature that isn't exactly 64 bytes — DER-encoded
// signatures (the SignASN1 form) have a different length and shape and
// MUST NOT be silently accepted on the JWS wire.
func ecdsaVerifyJWS(pub *ecdsa.PublicKey, message, sig []byte) bool {
	if len(sig) != 2*p256CoordinateBytes {
		return false
	}
	r := new(big.Int).SetBytes(sig[:p256CoordinateBytes])
	s := new(big.Int).SetBytes(sig[p256CoordinateBytes:])
	digest := sha256.Sum256(message)
	return ecdsa.Verify(pub, digest[:], r, s)
}

// Revoke adds the token to the in-memory deny list. Returns an error when
// the token wasn't signed by this issuer, so revokeAcrossIssuers
// correctly attributes ownership.
func (j *ECDSAJWTIssuer) Revoke(ctx context.Context, token string) error {
	if _, err := j.Validate(ctx, token); err != nil {
		return err
	}
	j.revokedMu.Lock()
	defer j.revokedMu.Unlock()
	j.revoked[token] = struct{}{}
	return nil
}

// IssueIDToken signs an OIDC ID Token with the same ES256 key as the
// access token issuer.
func (j *ECDSAJWTIssuer) IssueIDToken(ctx context.Context, req *oidc.IDTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("ecdsa: id token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = j.tokenTTL
	}
	now := time.Now()
	header := ecdsaHeader{Alg: jwtAlgES256, Typ: jwtTyp, Kid: kid}
	payload := ed25519IDPayload{
		Iss:   j.issuer,
		Sub:   req.Subject,
		Aud:   req.Audience,
		Exp:   now.Add(ttl).Unix(),
		Iat:   now.Unix(),
		Nonce: req.Nonce,
		AMR:   req.AMR,
		ACR:   req.ACR,
		AZP:   req.AZP,
		SID:   req.SID,
		Extra: req.Claims,
	}
	if !req.AuthTime.IsZero() {
		payload.AuthTime = req.AuthTime.Unix()
	}
	signingInput, err := ecdsaIDSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return "", fmt.Errorf("ecdsa: sign id token: %w", err)
	}
	return string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// SignUserInfo implements oidc.UserinfoSigner — same ES256 key as access
// + ID tokens. Stamps iss/aud per OIDC Core §5.3.2 unless the caller set
// them explicitly.
func (j *ECDSAJWTIssuer) SignUserInfo(ctx context.Context, audience string, claims map[string]any) (string, error) {
	sgn, kid := j.currentKey()
	if claims == nil {
		claims = make(map[string]any)
	}
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = j.issuer
	}
	if audience != "" {
		if _, ok := claims["aud"]; !ok {
			claims["aud"] = audience
		}
	}
	return j.signClaims(ctx, sgn, kid, jwtTyp, claims)
}

// SignMetadata implements oidc.MetadataSigner — RFC 8414 §2.1 signed
// discovery metadata, same ES256 key.
func (j *ECDSAJWTIssuer) SignMetadata(ctx context.Context, claims map[string]any) (string, error) {
	if claims == nil {
		return "", nil
	}
	sgn, kid := j.currentKey()
	return j.signClaims(ctx, sgn, kid, jwtTyp, claims)
}

// signClaims is the shared JWS assembler for the free-form claim-map
// signers (userinfo, metadata).
func (j *ECDSAJWTIssuer) signClaims(ctx context.Context, sgn ECDSASigner, kid, typ string, claims map[string]any) (string, error) {
	header := ecdsaHeader{Alg: jwtAlgES256, Typ: typ, Kid: kid}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := sgn.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("ecdsa: sign claims: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// lookupVerifyKey selects the verification key matching the JWT header's
// kid. Empty kid falls back to the primary (legacy tokens); then the local
// verifyKeys; then the adopted peer keys (peerVerifyKeys); a supplied but
// unrecognised kid returns nil so Validate fails closed.
//
// Lock discipline: read the active key + local verifyKeys under keyMu,
// release it FULLY, then read peerVerifyKeys under peerKeysMu. The two
// mutexes are never held nested, so there is no lock-ordering deadlock and no
// double-unlock. The ES256 alg gate in Validate runs BEFORE this lookup, so an
// adopted ES256 peer key is only ever reachable via the ES256 verify path —
// adoption cannot weaken the alg-confusion defense.
func (j *ECDSAJWTIssuer) lookupVerifyKey(kid string) *ecdsa.PublicKey {
	j.keyMu.RLock()
	if kid == "" {
		pub := j.publicKey
		j.keyMu.RUnlock()
		return pub
	}
	pub, ok := j.verifyKeys[kid]
	j.keyMu.RUnlock()
	if ok {
		return pub
	}

	// Fall through to adopted peer keys under a SEPARATE lock — keyMu is
	// already released above, so the two are never held simultaneously.
	j.peerKeysMu.RLock()
	defer j.peerKeysMu.RUnlock()
	if pub, ok := j.peerVerifyKeys[kid]; ok {
		return pub
	}
	return nil
}

// JWKS publishes the EC public key(s) per RFC 7518 §6.2: kty "EC", crv
// "P-256", x/y as the fixed-width 32-byte affine coordinates. Emits the
// primary key first, then LOCAL verify-only keys in fingerprint-sorted order,
// then ADOPTED PEER verify-only keys in fingerprint-sorted order (stable ETag)
// so a rotation keeps pre-swap tokens verifiable and any replica's token
// verifies anywhere.
//
// Lock discipline: snapshot the active key + local verifyKeys under keyMu and
// release it FULLY before acquiring peerKeysMu. The two mutexes are never held
// nested (independent lock order), so there is no double-unlock and no
// deadlock.
func (j *ECDSAJWTIssuer) JWKS(_ context.Context) ([]sso.JWK, error) {
	j.keyMu.RLock()
	keyID := j.keyID
	out := []sso.JWK{ecPublicJWK(keyID, j.publicKey)}
	verifyKids := make([]string, 0, len(j.verifyKeys))
	for kid := range j.verifyKeys {
		if kid == keyID {
			continue
		}
		verifyKids = append(verifyKids, kid)
	}
	// Snapshot the matching public keys while still under keyMu.
	local := make(map[string]*ecdsa.PublicKey, len(verifyKids))
	for _, kid := range verifyKids {
		local[kid] = j.verifyKeys[kid]
	}
	j.keyMu.RUnlock()

	sortStrings(verifyKids)
	for _, kid := range verifyKids {
		out = append(out, ecPublicJWK(kid, local[kid]))
	}

	// Adopted peer keys under a SEPARATE lock — keyMu is already released.
	j.peerKeysMu.RLock()
	peerKids := make([]string, 0, len(j.peerVerifyKeys))
	for kid := range j.peerVerifyKeys {
		peerKids = append(peerKids, kid)
	}
	peer := make(map[string]*ecdsa.PublicKey, len(peerKids))
	for _, kid := range peerKids {
		peer[kid] = j.peerVerifyKeys[kid]
	}
	j.peerKeysMu.RUnlock()

	sortStrings(peerKids)
	for _, kid := range peerKids {
		out = append(out, ecPublicJWK(kid, peer[kid]))
	}
	return out, nil
}

// ecPublicJWK builds the RFC 7518 §6.2 EC JWK for a P-256 public key.
func ecPublicJWK(kid string, pub *ecdsa.PublicKey) sso.JWK {
	xb := make([]byte, p256CoordinateBytes)
	yb := make([]byte, p256CoordinateBytes)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	return sso.JWK{
		Kty: jwkKtyEC,
		Crv: jwkCrvP256,
		Kid: kid,
		X:   base64.RawURLEncoding.EncodeToString(xb),
		Y:   base64.RawURLEncoding.EncodeToString(yb),
		Use: jwkUseSig,
		Alg: jwtAlgES256,
	}
}

// ecdsaSigningInput JOSE-encodes the access-token header + payload.
func ecdsaSigningInput(header ecdsaHeader, payload ed25519Payload) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)), nil
}

// ecdsaIDSigningInput is the ID-token mirror of ecdsaSigningInput.
func ecdsaIDSigningInput(header ecdsaHeader, payload ed25519IDPayload) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)), nil
}

// ecdsaFingerprintKid derives a deterministic kid from the P-256 public
// key — first 8 bytes of sha256 over the SEC1 uncompressed point,
// base64url-encoded. Same key always yields the same kid (so replicas
// sharing a key agree on JWKS lookups).
func ecdsaFingerprintKid(pub *ecdsa.PublicKey) string {
	point := elliptic.Marshal(pub.Curve, pub.X, pub.Y) //nolint:staticcheck // SEC1 point is the stable kid input across Go versions
	sum := sha256.Sum256(point)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// IssueLogoutToken mints an OIDC BCL 1.0 §2.4 Back-Channel Logout token
// with the same ES256 key as access + ID tokens.
func (j *ECDSAJWTIssuer) IssueLogoutToken(ctx context.Context, req *sso.LogoutTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("ecdsa: logout token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultLogoutTokenTTL
	}
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("ecdsa: generate jti: %w", err)
	}
	now := time.Now()
	header := ecdsaHeader{Alg: jwtAlgES256, Typ: logoutTokenTyp, Kid: kid}
	payload := ed25519LogoutPayload{
		Iss:    j.issuer,
		Sub:    req.Subject,
		Aud:    req.Audience,
		Iat:    now.Unix(),
		Exp:    now.Add(ttl).Unix(),
		JTI:    jti,
		Events: map[string]json.RawMessage{backchannelLogoutEvent: json.RawMessage("{}")},
		SID:    req.SID,
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := sgn.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("ecdsa: sign logout token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// AcceptsTokenFormat implements sso.TokenFormatHinter — a compact JWS has
// exactly two dots between three segments. Lets the multi-issuer
// dispatcher skip this issuer for non-JWT tokens. Note: an EdDSA JWT also
// has two dots and so reaches Validate, where the ES256 alg allowlist
// rejects it before any signature work.
func (j *ECDSAJWTIssuer) AcceptsTokenFormat(token string) bool {
	if token == "" {
		return false
	}
	parts := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts++
			if parts > 2 {
				return false
			}
		}
	}
	return parts == 2
}

// Compile-time interface guards.
var (
	_ sso.TokenIssuer       = (*ECDSAJWTIssuer)(nil)
	_ oidc.IDTokenIssuer    = (*ECDSAJWTIssuer)(nil)
	_ oidc.UserinfoSigner   = (*ECDSAJWTIssuer)(nil)
	_ oidc.MetadataSigner   = (*ECDSAJWTIssuer)(nil)
	_ sso.LogoutTokenIssuer = (*ECDSAJWTIssuer)(nil)
	_ sso.TokenFormatHinter = (*ECDSAJWTIssuer)(nil)
	_ sso.JWKSProvider      = (*ECDSAJWTIssuer)(nil)
)
