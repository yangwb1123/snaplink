package defaultimpl

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/oidc"
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

func (j *RSAJWTIssuer) Issue(ctx context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	sgn, kid := j.currentKey()
	if subject == nil || subject.ID == "" {
		return nil, errors.New("rsa: subject required")
	}
	now := time.Now()
	effectiveTTL := j.tokenTTL
	if subject.TTL > 0 {
		effectiveTTL = subject.TTL
	}
	expiresAt := now.Add(effectiveTTL)

	header := rsaHeader{Alg: j.alg, Typ: jwtTypAT, Kid: kid}
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("rsa: generate jti: %w", err)
	}

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
	if len(subject.RequestedClaims) > 0 {
		payload.RequestedClaims = append(json.RawMessage(nil), subject.RequestedClaims...)
	}
	if len(subject.Resources) > 0 {
		payload.Aud = audClaim(append([]string(nil), subject.Resources...))
	}

	signingInput, err := rsaSigningInput(header, payload)
	if err != nil {
		return nil, err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return nil, fmt.Errorf("rsa: sign access token: %w", err)
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

func (j *RSAJWTIssuer) Validate(_ context.Context, token string) (*sso.TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("rsa: malformed token")
	}

	j.revokedMu.RLock()
	_, revoked := j.revoked[token]
	j.revokedMu.RUnlock()
	if revoked {
		return nil, errors.New("rsa: token revoked")
	}

	// RFC 9068 §4: enforce alg + typ BEFORE signature verification. This
	// issuer accepts ONLY its configured alg (RS256 xor PS256), so a token
	// minted with the other RSA padding — or EdDSA / ES256 / `none` — is
	// rejected here, never reaching the verify path. Strict kid->alg: the
	// RP can't pick the verification algorithm.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("rsa: header decode: %w", err)
	}
	var h rsaHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("rsa: header parse: %w", err)
	}
	if h.Alg != j.alg {
		return nil, fmt.Errorf("rsa: alg %q not accepted (issuer signs %q)", h.Alg, j.alg)
	}
	if h.Typ != "" {
		if _, ok := supportedJWTTypes[h.Typ]; !ok {
			return nil, fmt.Errorf("rsa: typ %q not in allowlist", h.Typ)
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("rsa: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]

	pub := j.lookupVerifyKey(h.Kid)
	if pub == nil {
		return nil, errors.New("rsa: unknown kid")
	}
	if !rsaVerifyJWS(pub, []byte(signingInput), sig, j.alg) {
		return nil, errors.New("rsa: signature invalid")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("rsa: payload decode: %w", err)
	}
	var p ed25519Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("rsa: payload parse: %w", err)
	}

	now := time.Now().Unix()
	skew := int64(j.maxClockSkew.Seconds())
	if p.Exp != 0 && now-skew >= p.Exp {
		return nil, errors.New("rsa: token expired")
	}
	if p.Nbf != 0 && now+skew < p.Nbf {
		return nil, errors.New("rsa: token not yet valid")
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
	if len(p.RequestedClaims) > 0 {
		claims.RequestedClaims = append(json.RawMessage(nil), p.RequestedClaims...)
	}
	return claims, nil
}

// rsaVerifyJWS verifies an RS256 (PKCS1v15) or PS256 (PSS) signature over
// SHA-256, selected by alg.
func rsaVerifyJWS(pub *rsa.PublicKey, message, sig []byte, alg string) bool {
	digest := sha256.Sum256(message)
	if alg == jwtAlgPS256 {
		return rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}) == nil
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
}

// Revoke adds the token to the in-memory, exp-bounded deny list. Errors when
// the token wasn't signed by this issuer, so revokeAcrossIssuers attributes
// ownership. Keyed by the token's `exp` so markRevoked can lazily prune
// past-exp entries (prune-not-early; see revocation_set.go).
func (j *RSAJWTIssuer) Revoke(ctx context.Context, token string) error {
	claims, err := j.Validate(ctx, token)
	if err != nil {
		return err
	}
	exp := claims.ExpiresAt.Unix()
	j.revokedMu.Lock()
	markRevoked(j.revoked, token, exp)
	store := j.revocationStore
	j.revokedMu.Unlock()
	// Best-effort durable persist (restart-survival); the in-process revoke
	// already took effect, so a store outage must not fail the revoke.
	if store != nil {
		_ = store.Revoke(ctx, token, exp)
	}
	return nil
}

// SeedRevocations re-seeds the in-process deny-set from the wired
// RevocationStore at boot so a pre-restart revocation is honored again.
// nil store = no-op. See RevocationStore.
func (j *RSAJWTIssuer) SeedRevocations(ctx context.Context) error {
	if j.revocationStore == nil {
		return nil
	}
	j.revokedMu.Lock()
	defer j.revokedMu.Unlock()
	return seedRevokedFromStore(ctx, j.revoked, j.revocationStore)
}

// WithRSARevocationStore wires a durable RevocationStore (restart-survival;
// call SeedRevocations after construction). nil = in-process only.
func WithRSARevocationStore(store RevocationStore) RSAOption {
	return func(j *RSAJWTIssuer) { j.revocationStore = store }
}

// IssueIDToken signs an OIDC ID Token with the same RSA key.
func (j *RSAJWTIssuer) IssueIDToken(ctx context.Context, req *oidc.IDTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("rsa: id token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = j.tokenTTL
	}
	now := time.Now()
	header := rsaHeader{Alg: j.alg, Typ: jwtTyp, Kid: kid}
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
	// OIDC Core §3.1.3.6: bind the id_token to its companion access_token.
	// j.alg is RS256 or PS256 — both hash with SHA-256.
	payload.AtHash = accessTokenHash(j.alg, req.AccessToken)
	// Native SSO 1.0 §3.1: ds_hash binds an accompanying device_secret.
	payload.DsHash = accessTokenHash(j.alg, req.DeviceSecret)
	signingInput, err := rsaIDSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return "", fmt.Errorf("rsa: sign id token: %w", err)
	}
	return string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// SignUserInfo implements oidc.UserinfoSigner — same RSA key. Stamps
// iss/aud per OIDC Core §5.3.2 unless the caller set them.
func (j *RSAJWTIssuer) SignUserInfo(ctx context.Context, audience string, claims map[string]any) (string, error) {
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
// discovery metadata, same RSA key.
func (j *RSAJWTIssuer) SignMetadata(ctx context.Context, claims map[string]any) (string, error) {
	if claims == nil {
		return "", nil
	}
	sgn, kid := j.currentKey()
	return j.signClaims(ctx, sgn, kid, jwtTyp, claims)
}

// signClaims is the shared JWS assembler for the free-form claim-map
// signers (userinfo, metadata).
func (j *RSAJWTIssuer) signClaims(ctx context.Context, sgn RSASigner, kid, typ string, claims map[string]any) (string, error) {
	header := rsaHeader{Alg: j.alg, Typ: typ, Kid: kid}
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
		return "", fmt.Errorf("rsa: sign claims: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// lookupVerifyKey selects the verification key matching the header kid.
// Empty kid falls back to the primary (legacy tokens); then the local
// verifyKeys; then the adopted peer keys (peerVerifyKeys); an unrecognised kid
// returns nil so Validate fails closed.
//
// Lock discipline: read the active key + local verifyKeys under keyMu,
// release it FULLY, then read peerVerifyKeys under peerKeysMu. The two
// mutexes are never held nested, so there is no lock-ordering deadlock and no
// double-unlock. The alg gate in Validate (h.Alg == j.alg) runs BEFORE this
// lookup, so an adopted RS256 peer key is only ever reachable on an RS256
// issuer's verify path (PS256 likewise) — adoption cannot weaken the
// alg-confusion defense or blur the RS256/PS256 boundary.
func (j *RSAJWTIssuer) lookupVerifyKey(kid string) *rsa.PublicKey {
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

// JWKS publishes the RSA public key(s) per RFC 7518 §6.3: kty "RSA", n/e.
// Emits the primary first, then LOCAL verify-only keys in fingerprint-sorted
// order, then ADOPTED PEER verify-only keys in fingerprint-sorted order (stable
// ETag) so a rotation keeps pre-swap tokens verifiable and any replica's token
// verifies anywhere. Every entry carries this issuer's configured alg (RS256
// xor PS256) — a peer key only reaches this issuer when the Server's alg-match
// gate already confirmed the peer announced the same alg, so stamping j.alg is
// correct.
//
// Lock discipline: snapshot the active key + local verifyKeys under keyMu and
// release it FULLY before acquiring peerKeysMu. The two mutexes are never held
// nested (independent lock order), so there is no double-unlock and no
// deadlock.
func (j *RSAJWTIssuer) JWKS(_ context.Context) ([]sso.JWK, error) {
	j.keyMu.RLock()
	keyID := j.keyID
	alg := j.alg
	out := []sso.JWK{rsaPublicJWK(keyID, j.publicKey, alg)}
	verifyKids := make([]string, 0, len(j.verifyKeys))
	for kid := range j.verifyKeys {
		if kid == keyID {
			continue
		}
		verifyKids = append(verifyKids, kid)
	}
	// Snapshot the matching public keys while still under keyMu.
	local := make(map[string]*rsa.PublicKey, len(verifyKids))
	for _, kid := range verifyKids {
		local[kid] = j.verifyKeys[kid]
	}
	j.keyMu.RUnlock()

	sortStrings(verifyKids)
	for _, kid := range verifyKids {
		out = append(out, rsaPublicJWK(kid, local[kid], alg))
	}

	// Adopted peer keys under a SEPARATE lock — keyMu is already released.
	j.peerKeysMu.RLock()
	peerKids := make([]string, 0, len(j.peerVerifyKeys))
	for kid := range j.peerVerifyKeys {
		peerKids = append(peerKids, kid)
	}
	peer := make(map[string]*rsa.PublicKey, len(peerKids))
	for _, kid := range peerKids {
		peer[kid] = j.peerVerifyKeys[kid]
	}
	j.peerKeysMu.RUnlock()

	sortStrings(peerKids)
	for _, kid := range peerKids {
		out = append(out, rsaPublicJWK(kid, peer[kid], alg))
	}
	return out, nil
}

// rsaPublicJWK builds the RFC 7518 §6.3 RSA JWK: n = big-endian modulus,
// e = big-endian public exponent, both base64url (minimal, no leading
// zero octets) per the spec.
func rsaPublicJWK(kid string, pub *rsa.PublicKey, alg string) sso.JWK {
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(pub.E))
	// Trim leading zero octets (JWKS uses the minimal big-endian form).
	i := 0
	for i < len(eBytes)-1 && eBytes[i] == 0 {
		i++
	}
	return sso.JWK{
		Kty: jwkKtyRSA,
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes[i:]),
		Use: jwkUseSig,
		Alg: alg,
	}
}

// rsaSigningInput JOSE-encodes the access-token header + payload.
func rsaSigningInput(header rsaHeader, payload ed25519Payload) ([]byte, error) {
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

// rsaIDSigningInput is the ID-token mirror of rsaSigningInput.
func rsaIDSigningInput(header rsaHeader, payload ed25519IDPayload) ([]byte, error) {
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

// rsaFingerprintKid derives a deterministic kid from the public key —
// first 8 bytes of sha256 over the PKIX DER encoding, base64url. Same key
// always yields the same kid (so replicas sharing a key agree on JWKS).
func rsaFingerprintKid(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// Fall back to the modulus bytes — still deterministic.
		der = pub.N.Bytes()
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// IssueLogoutToken mints an OIDC BCL 1.0 §2.4 logout token with the same
// RSA key.
func (j *RSAJWTIssuer) IssueLogoutToken(ctx context.Context, req *sso.LogoutTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("rsa: logout token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultLogoutTokenTTL
	}
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("rsa: generate jti: %w", err)
	}
	now := time.Now()
	header := rsaHeader{Alg: j.alg, Typ: logoutTokenTyp, Kid: kid}
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
		return "", fmt.Errorf("rsa: sign logout token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// SignJWT signs an arbitrary claims object as a compact JWS using the
// SAME RSA key (and kid) as access + ID + logout tokens, stamping the
// supplied `typ` in the JOSE header. It is the generic-JWT seam the
// CAEP/SSF transmitter reuses to mint Security Event Tokens (RFC 8417,
// `typ: secevent+jwt`) — the SET verifies against the key already in
// JWKS, so no new RP trust setup is needed. See the Ed25519 sibling for
// the full rationale; typ MUST be non-empty.
func (j *RSAJWTIssuer) SignJWT(ctx context.Context, typ string, claims any) (string, error) {
	if typ == "" {
		return "", errors.New("rsa: sign jwt requires a typ header")
	}
	sgn, kid := j.currentKey()
	header := rsaHeader{Alg: j.alg, Typ: typ, Kid: kid}
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
		return "", fmt.Errorf("rsa: sign jwt (typ=%s): %w", typ, err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// AcceptsTokenFormat implements sso.TokenFormatHinter — a compact JWS has
// exactly two dots. An EdDSA/ES256 JWT also matches and reaches Validate,
// where the alg gate rejects it before any signature work.
func (j *RSAJWTIssuer) AcceptsTokenFormat(token string) bool {
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

// Compile-time interface guards. The caep.JWTSigner guard is deliberately
// NOT here: it lives in caep/jwtsigner_guard_test.go so the foundational
// defaultimpl package never imports the peripheral caep subsystem. SignJWT
// satisfies caep.JWTSigner structurally regardless.
var (
	_ sso.TokenIssuer       = (*RSAJWTIssuer)(nil)
	_ oidc.IDTokenIssuer    = (*RSAJWTIssuer)(nil)
	_ oidc.UserinfoSigner   = (*RSAJWTIssuer)(nil)
	_ oidc.MetadataSigner   = (*RSAJWTIssuer)(nil)
	_ sso.LogoutTokenIssuer = (*RSAJWTIssuer)(nil)
	_ sso.TokenFormatHinter = (*RSAJWTIssuer)(nil)
	_ sso.JWKSProvider      = (*RSAJWTIssuer)(nil)
)
