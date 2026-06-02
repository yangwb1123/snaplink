package defaultimpl

import "github.com/snaplink/sso/oidc"

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso"
)

// Ed25519 JWT constants.
const (
	jwtAlgEdDSA   = "EdDSA"
	jwtTyp        = "JWT"    // OIDC ID tokens
	jwtTypAT      = "at+jwt" // RFC 9068 §2.1 — JWT Profile for OAuth 2.0 Access Tokens
	jwkKtyOKP     = "OKP"
	jwkCrvEd25519 = "Ed25519"
	jwkUseSig     = "sig"
)

// supportedJWTAlgs is the Validate-time allowlist. Per RFC 9068 §4
// the recipient MUST reject tokens whose `alg` is outside the
// allowlist (in particular: never `none`, never asymmetric algs
// confused with symmetric ones). Today we only sign EdDSA; extend
// this list only when a new signer is wired AND validated against
// the JWT algorithm-confusion threat model.
var supportedJWTAlgs = map[string]struct{}{
	jwtAlgEdDSA: {},
}

// supportedJWTTypes is the Validate-time `typ` allowlist for
// access tokens. `at+jwt` is the RFC 9068 §2.1 canonical value;
// `JWT` stays accepted for backward compatibility with tokens
// minted before the profile was wired (in-flight tokens at
// upgrade time keep verifying until their natural expiry).
// `application/at+jwt` is the long-form variant some libraries
// emit per RFC 9068 §2.1 footnote.
//
// Note: logout tokens carry `typ: logout+jwt` and MUST NOT be
// validated through this allowlist — they have a separate
// shape (events claim, no scope/aud-array, etc.) and a
// dedicated verifier on the RP side. Validate here is
// access-token only.
var supportedJWTTypes = map[string]struct{}{
	jwtTypAT:             {},
	"application/at+jwt": {},
	jwtTyp:               {},
}

// Ed25519JWTIssuer signs 3-segment JWTs (header.payload.signature) with an
// Ed25519 private key. The public key is published via the JWKS endpoint so
// downstream gateways (e.g. OpenResty + lua-resty-jwt) can verify tokens
// locally without round-tripping back to the SSO server.
//
// Revocation is in-memory: tokens are added to a deny set on Revoke and
// Validate consults it. Persistent / distributed revocation requires
// replacing the deny set with a Redis/DB-backed implementation.
type Ed25519JWTIssuer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	issuer     string
	tokenTTL   time.Duration

	// maxClockSkew is the leeway granted to inbound exp/nbf checks
	// per RFC 7519 §4.1.4-5 ("Implementers MAY provide for some
	// small leeway"). Zero = exact comparison (the historical
	// behavior). Positive values widen the acceptance window in
	// both directions — a token whose exp is X seconds in the past
	// is still accepted when maxClockSkew >= X.
	maxClockSkew time.Duration

	// verifyKeys maps kid → public key for additional verification-
	// only keys (previously-active signers being phased out). The
	// primary publicKey is registered here too at construction time
	// so Validate has one lookup path. Operators add additional
	// retired-but-still-trusted keys via [WithEd25519VerifyKey] so
	// in-flight tokens signed by the old key stay valid through
	// their TTL window after a rotation.
	verifyKeys map[string]ed25519.PublicKey

	revokedMu sync.RWMutex
	revoked   map[string]struct{}

	// keyMu guards the active signing key (signer/keyID/publicKey) and
	// the verifyKeys map so RotateKey can swap them at runtime without
	// racing concurrent Issue/Validate/JWKS calls. Construction-time
	// option mutation runs before the issuer is shared, so it needs no
	// lock; only runtime rotation does.
	keyMu sync.RWMutex

	// peerVerifyKeys holds VERIFY-ONLY public keys adopted from OTHER
	// replicas in a leaderless multi-replica deployment (see package
	// signingkeys). It is deliberately SEPARATE from verifyKeys, guarded
	// by its own mutex, so that this replica's local key lifecycle —
	// RotateKey / RetireKey — NEVER touches peer keys: peer-key lifecycle
	// is owned by the registry/peer side, not by local rotation. The two
	// mutexes are never held nested; lock order is independent (acquire
	// one, fully release, then acquire the other) — see lookupVerifyKey
	// and JWKS for the discipline.
	peerKeysMu     sync.RWMutex
	peerVerifyKeys map[string]ed25519.PublicKey

	// signer performs the raw EdDSA signing. Defaults to an in-process
	// signer holding privateKey; WithEd25519ExternalSigner swaps in a
	// KMS/HSM-backed signer (private key never enters this process).
	signer Ed25519Signer
}

// currentKey snapshots the active signer + its kid together under the
// read lock, so a token's header kid and its signature always come from
// the same key even if RotateKey fires mid-issuance.
func (j *Ed25519JWTIssuer) currentKey() (Ed25519Signer, string) {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	return j.signer, j.keyID
}

// Ed25519Signer abstracts the raw EdDSA signing operation so the
// process-held private key can be swapped for a KMS/HSM-backed signer
// without touching JWT assembly. Sign receives the JWS signing input
// (the "header.payload" bytes) and returns the 64-byte Ed25519
// signature. It MAY return an error (e.g. a KMS round-trip failure);
// every call site propagates it, so token issuance fails closed rather
// than emitting an unsigned token.
type Ed25519Signer interface {
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

// softwareEd25519Signer is the default in-process signer.
type softwareEd25519Signer struct{ priv ed25519.PrivateKey }

func (s softwareEd25519Signer) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

type Ed25519Option func(*Ed25519JWTIssuer)

func WithEd25519Issuer(name string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.issuer = name }
}

func WithEd25519TokenTTL(ttl time.Duration) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.tokenTTL = ttl }
}

// WithEd25519MaxClockSkew widens the inbound exp/nbf validation
// window per RFC 7519 §4.1.4-5. Useful when AS and resource server
// clocks drift (NTP-managed clocks routinely drift 100ms-1s; a
// well-managed pair drifts under 5s). Default 0 = exact comparison.
// Recommended production value: 30s-2min. Going much higher widens
// the window an attacker has to replay an expired token.
func WithEd25519MaxClockSkew(skew time.Duration) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		if skew > 0 {
			j.maxClockSkew = skew
		}
	}
}

// WithEd25519Key uses the supplied keypair instead of generating one.
// Useful for tests and for long-lived deployments where the key must persist
// across process restarts.
func WithEd25519Key(priv ed25519.PrivateKey) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		j.privateKey = priv
		j.publicKey = priv.Public().(ed25519.PublicKey)
	}
}

// WithEd25519KeyID overrides the auto-derived kid.
func WithEd25519KeyID(kid string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.keyID = kid }
}

// WithEd25519VerifyKey adds a public key the issuer will accept on
// Validate but will NOT use to sign new tokens — the retired-signer
// half of a rotation. Operators add the OUTGOING key here for the
// duration of the access-token TTL after a key swap, so tokens
// minted before the swap stay verifiable until they expire
// naturally. Once the TTL window has passed, remove the option on
// the next deployment and the retired key disappears from JWKS.
//
// kid MUST be distinct from the primary signing key's kid and from
// every other verify-only key (key lookup is by kid in Validate).
// Idempotent: registering the same kid twice updates the public
// key without erroring — useful for testing rotations.
func WithEd25519VerifyKey(kid string, pub ed25519.PublicKey) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		if j.verifyKeys == nil {
			j.verifyKeys = make(map[string]ed25519.PublicKey, 2)
		}
		j.verifyKeys[kid] = pub
	}
}

func NewEd25519JWTIssuer(opts ...Ed25519Option) *Ed25519JWTIssuer {
	j := &Ed25519JWTIssuer{
		issuer:   sso.DefaultIssuer,
		tokenTTL: defaultTokenTTL,
		revoked:  make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(j)
	}
	// Generate an in-process key only when neither a private key nor an
	// external signer was supplied — an external signer holds its own
	// (KMS/HSM) key and provides the public half via the option.
	if j.privateKey == nil && j.signer == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(fmt.Sprintf("ed25519: generate key: %v", err))
		}
		j.privateKey = priv
		j.publicKey = pub
	}
	if j.signer == nil {
		j.signer = softwareEd25519Signer{priv: j.privateKey}
	}
	if j.keyID == "" {
		j.keyID = fingerprintKid(j.publicKey)
	}
	if j.verifyKeys == nil {
		j.verifyKeys = make(map[string]ed25519.PublicKey, 1)
	}
	// Always register the primary signing key in the verify map so
	// Validate has one lookup path (no special-case for "primary").
	j.verifyKeys[j.keyID] = j.publicKey
	// peerVerifyKeys starts empty: it only ever populates via
	// AdoptVerifyKey when this replica is wired into a shared signing-key
	// registry. With no registry, it stays nil-empty forever, so JWKS()
	// and Validate() are byte-identical to a build that lacks this feature.
	j.peerVerifyKeys = make(map[string]ed25519.PublicKey)
	return j
}

// AdoptVerifyKey installs a peer replica's signing public key as a
// VERIFY-ONLY key, so this replica's JWKS() serves it and Validate()
// accepts tokens it signed (see package signingkeys). It NEVER affects
// signing — this replica keeps minting tokens only with its own private
// key. Idempotent: re-adopting the same kid updates the public key in
// place (a peer rotation re-publishes under the same kid only if it pins
// the key; normally a rotation publishes a new kid + drops the old).
//
// Defensive collision guards: kid must be non-empty, pub must be a valid
// Ed25519 public key, and kid must NOT collide with this replica's active
// signing kid or any LOCAL verify key (verifyKeys). Such a collision would
// mean two distinct keys claim one kid, breaking the O(1) kid->key lookup
// — it can only happen via a fingerprint collision or a misconfiguration,
// and is rejected loudly rather than silently shadowing the local key.
func (j *Ed25519JWTIssuer) AdoptVerifyKey(kid string, pub ed25519.PublicKey) error {
	if kid == "" {
		return errors.New("ed25519: adopt verify key: empty kid")
	}
	if pub == nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519: adopt verify key %q: invalid public key length %d", kid, len(pub))
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
		return fmt.Errorf("ed25519: adopt verify key %q: kid collides with a local signing/verify key", kid)
	}

	j.peerKeysMu.Lock()
	defer j.peerKeysMu.Unlock()
	if j.peerVerifyKeys == nil {
		j.peerVerifyKeys = make(map[string]ed25519.PublicKey, 1)
	}
	j.peerVerifyKeys[kid] = pub
	return nil
}

// DropVerifyKey removes a previously adopted peer key (idempotent). It
// operates ONLY on peerVerifyKeys, never on local verifyKeys, so it can
// never strand a local signing/retired key — peer and local key lifecycles
// are independent.
func (j *Ed25519JWTIssuer) DropVerifyKey(kid string) {
	j.peerKeysMu.Lock()
	defer j.peerKeysMu.Unlock()
	delete(j.peerVerifyKeys, kid)
}

// WithEd25519ExternalSigner injects a signer whose private key lives
// outside this process (AWS KMS, GCP KMS, an HSM via PKCS#11). pub is
// the corresponding Ed25519 public key — published in JWKS and used by
// Validate — and kid names it in issued tokens' headers. The issuer
// never generates or holds a private key in this mode.
//
// pub MUST be the public half of the key the signer signs with;
// otherwise every issued token fails verification. kid SHOULD be stable
// across replicas sharing the same external key so JWKS lookups agree.
func WithEd25519ExternalSigner(signer Ed25519Signer, pub ed25519.PublicKey, kid string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		j.signer = signer
		j.publicKey = pub
		if kid != "" {
			j.keyID = kid
		}
	}
}

// PublicKey returns the verification key so callers can pre-populate
// caches or pass it to non-JWKS verifiers.
func (j *Ed25519JWTIssuer) PublicKey() ed25519.PublicKey {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	return j.publicKey
}

// KeyID returns the kid string embedded in every issued token's header.
func (j *Ed25519JWTIssuer) KeyID() string {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	return j.keyID
}

// RotateKey promotes a new signing key, demoting the current signing
// key to verify-only so tokens it already minted stay valid through
// their TTL. Pass nil priv to generate a fresh key; pass an explicit
// key to pin it (multi-replica deployments rotate to the SAME key on
// every node so JWKS agrees). Returns the new kid. The new public key
// appears in JWKS immediately; the demoted key remains until RetireKey
// drops it. Safe for concurrent use with Issue/Validate/JWKS.
//
// This rotates the in-process software signer. External (KMS/HSM)
// signers are rotated by their own backend; use WithEd25519VerifyKey
// at construction to trust their retired keys.
func (j *Ed25519JWTIssuer) RotateKey(priv ed25519.PrivateKey) (string, error) {
	if priv == nil {
		var err error
		if _, priv, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return "", fmt.Errorf("ed25519: rotate generate key: %w", err)
		}
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("ed25519: rotate: invalid private key")
	}
	newKID := fingerprintKid(pub)

	j.keyMu.Lock()
	defer j.keyMu.Unlock()
	// Demote the outgoing key: keep its public half in verifyKeys so its
	// in-flight tokens verify until they expire.
	if j.publicKey != nil && j.keyID != "" {
		if j.verifyKeys == nil {
			j.verifyKeys = make(map[string]ed25519.PublicKey, 2)
		}
		j.verifyKeys[j.keyID] = j.publicKey
	}
	j.privateKey = priv
	j.publicKey = pub
	j.keyID = newKID
	j.signer = softwareEd25519Signer{priv: priv}
	j.verifyKeys[newKID] = pub
	return newKID, nil
}

// RetireKey removes a verify-only key (typically a previously-rotated
// signer whose tokens have all expired) so it stops appearing in JWKS.
// Refuses to retire the active signing key — that would strand every
// live token. Safe for concurrent use.
func (j *Ed25519JWTIssuer) RetireKey(kid string) error {
	j.keyMu.Lock()
	defer j.keyMu.Unlock()
	if kid == j.keyID {
		return errors.New("ed25519: cannot retire the active signing key")
	}
	delete(j.verifyKeys, kid)
	return nil
}

type ed25519Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type ed25519Payload struct {
	Iss   string            `json:"iss,omitempty"`
	Sub   string            `json:"sub,omitempty"`
	Aud   audClaim          `json:"aud,omitempty"`
	Exp   int64             `json:"exp,omitempty"`
	Nbf   int64             `json:"nbf,omitempty"`
	Iat   int64             `json:"iat,omitempty"`
	Scope string            `json:"scope,omitempty"`
	Extra map[string]string `json:"ext,omitempty"`

	// RFC 9068 §2.2 access-token claims.
	ClientID string             `json:"client_id,omitempty"`
	JTI      string             `json:"jti,omitempty"`
	AuthTime int64              `json:"auth_time,omitempty"`
	ACR      string             `json:"acr,omitempty"`
	AMR      []string           `json:"amr,omitempty"`
	SID      string             `json:"sid,omitempty"`
	CNF      *confirmationClaim `json:"cnf,omitempty"`

	// RFC 9396 — Rich Authorization Requests. Pass-through of
	// the original `authorization_details` array as raw JSON so
	// extension fields survive without an explicit schema here.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`

	// RFC 8693 §4.1 `act` claim for delegation chains. Populated
	// by the token-exchange grant when an actor_token is
	// presented; nil for direct (non-delegated) tokens.
	Act *actClaim `json:"act,omitempty"`
}

// confirmationClaim is RFC 7800 §3.1's `cnf` JSON object. RFC 9449
// §6 uses the `jkt` member to carry a DPoP key's JWK thumbprint;
// RFC 8705 §3.1 uses `x5t#S256` to carry the mTLS client cert
// thumbprint. A single token uses one mechanism — both fields
// populated simultaneously would be a caller bug.
type confirmationClaim struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// actClaim is the wire shape of `act`. Per RFC 8693 §4.1 the
// claim is a JSON object with at least `sub` and an optional
// nested `act` for multi-hop delegation chains. Mirrors
// sso.ActorClaim's structure on the public API side.
type actClaim struct {
	Sub string    `json:"sub,omitempty"`
	Act *actClaim `json:"act,omitempty"`
}

// actorChainToWire walks an sso.ActorClaim chain (outermost-first)
// into the wire-shape actClaim chain. nil-safe — returns nil so
// "no delegation" stays distinguishable from "empty chain" in the
// emitted JWT.
func actorChainToWire(a *sso.ActorClaim) *actClaim {
	if a == nil || a.Subject == "" {
		return nil
	}
	return &actClaim{Sub: a.Subject, Act: actorChainToWire(a.Actor)}
}

// wireChainToActor is the inverse: rebuild the sso.ActorClaim
// chain from a validated JWT's act tree. nil-safe.
func wireChainToActor(a *actClaim) *sso.ActorClaim {
	if a == nil || a.Sub == "" {
		return nil
	}
	return &sso.ActorClaim{Subject: a.Sub, Actor: wireChainToActor(a.Act)}
}

// audClaim handles RFC 7519 §4.1.3's polymorphic `aud` claim. Per
// the spec it's "an array of case-sensitive strings"; "in the
// special case when the JWT has one audience, the aud value MAY be
// a single case-sensitive string." OIDC ID tokens favor the
// single-string form; access tokens here favor the array form.
// Tolerating both lets one Validate path handle every shape.
type audClaim []string

func (a *audClaim) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*a = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

func (a audClaim) MarshalJSON() ([]byte, error) {
	// Single-audience tokens stay compact-string per OIDC convention;
	// multi-audience marshals as an array.
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// ed25519IDPayload is the ID-Token-specific claim set, distinct from
// access tokens because OIDC names some fields differently (aud is a
// scalar string when single-valued in many real deployments; auth_time
// is a first-class claim; nonce/amr/acr/azp are OIDC-specific).
type ed25519IDPayload struct {
	Iss      string            `json:"iss,omitempty"`
	Sub      string            `json:"sub,omitempty"`
	Aud      string            `json:"aud,omitempty"`
	Exp      int64             `json:"exp,omitempty"`
	Iat      int64             `json:"iat,omitempty"`
	Nonce    string            `json:"nonce,omitempty"`
	AuthTime int64             `json:"auth_time,omitempty"`
	AMR      []string          `json:"amr,omitempty"`
	ACR      string            `json:"acr,omitempty"`
	AZP      string            `json:"azp,omitempty"`
	SID      string            `json:"sid,omitempty"`
	Extra    map[string]string `json:"ext,omitempty"`
}

func (j *Ed25519JWTIssuer) Issue(ctx context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	sgn, kid := j.currentKey()
	if subject == nil || subject.ID == "" {
		return nil, errors.New("ed25519: subject required")
	}
	now := time.Now()
	// Per-issuance TTL override (Client.AccessTokenTTL) wins over
	// the issuer's configured tokenTTL. Zero = use the issuer's
	// default — preserves backwards compatibility for callers
	// that don't set Subject.TTL.
	effectiveTTL := j.tokenTTL
	if subject.TTL > 0 {
		effectiveTTL = subject.TTL
	}
	expiresAt := now.Add(effectiveTTL)

	// RFC 9068 §2.1: header `typ` MUST be `at+jwt` to distinguish
	// access tokens from other JWT shapes (ID tokens, generic JWT)
	// so strict resource servers can reject misrouted tokens.
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTypAT, Kid: kid}

	// RFC 9068 §2.2 REQUIRES jti — a unique identifier per token,
	// suitable for replay tracking + revocation lookup. 16 bytes
	// = 128 bits = collision-free at any practical issue rate.
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("ed25519: generate jti: %w", err)
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
	// RFC 8707 resource indicators flow through Subject.Resources
	// into the standard `aud` JWT claim. Resource servers verify
	// their own URI is in the array before accepting the token.
	if len(subject.Resources) > 0 {
		payload.Aud = audClaim(append([]string(nil), subject.Resources...))
	}

	signingInput, err := jwtSigningInput(header, payload)
	if err != nil {
		return nil, err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return nil, fmt.Errorf("ed25519: sign access token: %w", err)
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

// generateJTI mints a 16-byte (128-bit) base64url-encoded unique
// identifier for the `jti` claim per RFC 9068 §2.2.
func generateJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (j *Ed25519JWTIssuer) Validate(_ context.Context, token string) (*sso.TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("ed25519: malformed token")
	}

	j.revokedMu.RLock()
	_, revoked := j.revoked[token]
	j.revokedMu.RUnlock()
	if revoked {
		return nil, errors.New("ed25519: token revoked")
	}

	// RFC 9068 §4: parse the header explicitly so the algorithm
	// and typ allowlists are enforced BEFORE signature verification
	// even runs. Defends against alg-confusion attacks (e.g.
	// alg=none, alg=HS256-spoofed-with-RS256-public-key) and
	// against a token meant for a different shape (ID token,
	// generic JWT) being accepted as an access token.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("ed25519: header decode: %w", err)
	}
	var h ed25519Header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("ed25519: header parse: %w", err)
	}
	if _, ok := supportedJWTAlgs[h.Alg]; !ok {
		return nil, fmt.Errorf("ed25519: alg %q not in allowlist", h.Alg)
	}
	// Empty typ is tolerated for legacy tokens minted before this
	// gate landed (back-compat); a non-empty typ MUST be in the
	// allowlist.
	if h.Typ != "" {
		if _, ok := supportedJWTTypes[h.Typ]; !ok {
			return nil, fmt.Errorf("ed25519: typ %q not in allowlist", h.Typ)
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("ed25519: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]

	// Pick the verification key by the JWT header's kid. Tokens
	// without a kid (legacy) fall back to the primary key —
	// rotation needs every minted token to carry a kid for the
	// lookup to be O(1), which `Issue` does unconditionally.
	pub := j.lookupVerifyKey(parts[0])
	if pub == nil {
		return nil, errors.New("ed25519: unknown kid")
	}
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, errors.New("ed25519: signature invalid")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ed25519: payload decode: %w", err)
	}
	var p ed25519Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("ed25519: payload parse: %w", err)
	}

	now := time.Now().Unix()
	skew := int64(j.maxClockSkew.Seconds())
	if p.Exp != 0 && now-skew >= p.Exp {
		return nil, errors.New("ed25519: token expired")
	}
	if p.Nbf != 0 && now+skew < p.Nbf {
		return nil, errors.New("ed25519: token not yet valid")
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

// Revoke adds the token to an in-memory deny list. Returns an error when the
// token wasn't signed by this issuer, so that revokeAcrossIssuers correctly
// attributes ownership.
func (j *Ed25519JWTIssuer) Revoke(ctx context.Context, token string) error {
	if _, err := j.Validate(ctx, token); err != nil {
		return err
	}
	j.revokedMu.Lock()
	defer j.revokedMu.Unlock()
	j.revoked[token] = struct{}{}
	return nil
}

// IssueIDToken signs an OIDC ID Token using the same Ed25519 key as the
// access token issuer — by design, downstream relying parties verify
// both with one JWKS entry. ttl falls back to the issuer's tokenTTL
// when req.TTL is zero (matching access-token lifetime keeps
// expiration semantics consistent across the pair).
//
// All OIDC-mandated fields are stamped automatically (iss, sub, aud,
// exp, iat). Nonce / AuthTime / AMR / ACR / AZP / extra Claims are
// projected only when non-zero so the wire stays minimal — relying
// parties branch on field presence per OIDC Core §2.
func (j *Ed25519JWTIssuer) IssueIDToken(ctx context.Context, req *oidc.IDTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("ed25519: id token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = j.tokenTTL
	}
	now := time.Now()
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTyp, Kid: kid}
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
	signingInput, err := idTokenSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return "", fmt.Errorf("ed25519: sign id token: %w", err)
	}
	return string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// SignUserInfo implements [oidc.UserinfoSigner]. Wraps the supplied
// claim set in a JWS using the same signing key as access + ID
// tokens — RPs verify all three with one JWKS entry. Stamps `iss`
// (AS issuer) and `aud` (client_id) per OIDC Core §5.3.2; the
// caller-supplied claims override these only if they explicitly
// set them (extension claims merge naturally with the map).
func (j *Ed25519JWTIssuer) SignUserInfo(ctx context.Context, audience string, claims map[string]any) (string, error) {
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
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTyp, Kid: kid}
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
		return "", fmt.Errorf("ed25519: sign userinfo: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// SignMetadata implements [oidc.MetadataSigner]. Wraps the discovery
// document claims in a JWS using the same key as access + ID +
// userinfo tokens. Header includes `kid` so an RP that's already
// fetched JWKS can pick the right key for verification.
func (j *Ed25519JWTIssuer) SignMetadata(ctx context.Context, claims map[string]any) (string, error) {
	sgn, kid := j.currentKey()
	if claims == nil {
		return "", nil
	}
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTyp, Kid: kid}
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
		return "", fmt.Errorf("ed25519: sign metadata: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// idTokenSigningInput is the ID-token mirror of jwtSigningInput — same
// JOSE encoding, but parametrized on the ID payload shape.
func idTokenSigningInput(header ed25519Header, payload ed25519IDPayload) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	return []byte(encoded), nil
}

// lookupVerifyKey selects the verification key matching the JWT
// header's kid. Returns the primary publicKey when the header is
// missing kid (legacy tokens without a kid still verify under the
// primary), then the local verifyKeys, then the adopted peer keys
// (peerVerifyKeys), or nil when the kid is supplied but unrecognised so
// Validate can fail closed on an unknown signer.
//
// Lock discipline: read the active key + local verifyKeys under keyMu,
// release it FULLY, then read peerVerifyKeys under peerKeysMu. The two
// mutexes are never held nested, so there is no lock-ordering deadlock
// and no double-unlock. The alg gate in Validate runs BEFORE this lookup,
// so an adopted EdDSA peer key is only ever reachable via the EdDSA
// verify path — adoption cannot weaken the alg-confusion defense.
func (j *Ed25519JWTIssuer) lookupVerifyKey(headerB64 string) ed25519.PublicKey {
	raw, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil
	}
	var h ed25519Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil
	}

	j.keyMu.RLock()
	if h.Kid == "" {
		pub := j.publicKey
		j.keyMu.RUnlock()
		return pub
	}
	pub, ok := j.verifyKeys[h.Kid]
	j.keyMu.RUnlock()
	if ok {
		return pub
	}

	// Fall through to adopted peer keys under a SEPARATE lock — keyMu is
	// already released above, so the two are never held simultaneously.
	j.peerKeysMu.RLock()
	defer j.peerKeysMu.RUnlock()
	if pub, ok := j.peerVerifyKeys[h.Kid]; ok {
		return pub
	}
	return nil
}

// JWKS returns the issuer's public keys as JWKs for inclusion in
// /.well-known/jwks.json. During a key rotation this emits BOTH
// the primary signing key AND every WithEd25519VerifyKey retired
// key, so RPs that pulled a token before the rotation can still
// verify it after the swap. When peer keys have been adopted (a
// leaderless multi-replica deployment wired to a shared signing-key
// registry), those are emitted too as verify-only keys, so the union
// is published and any replica's token verifies anywhere.
//
// Output order: primary first, then LOCAL verify-only keys in
// fingerprint-sorted order, then ADOPTED PEER verify-only keys in
// fingerprint-sorted order. Stable across one process lifetime so the
// JWKS ETag stays valid until the key set actually changes.
//
// Lock discipline: snapshot the active key + local verifyKeys under
// keyMu and release it FULLY before acquiring peerKeysMu. The two
// mutexes are never held nested (independent lock order), so there is no
// double-unlock and no deadlock.
func (j *Ed25519JWTIssuer) JWKS(_ context.Context) ([]sso.JWK, error) {
	j.keyMu.RLock()
	keyID := j.keyID
	out := []sso.JWK{{
		Kty: jwkKtyOKP,
		Crv: jwkCrvEd25519,
		Kid: keyID,
		X:   base64.RawURLEncoding.EncodeToString(j.publicKey),
		Use: jwkUseSig,
		Alg: jwtAlgEdDSA,
	}}
	// Collect kids of LOCAL verify-only keys (skip the primary, already
	// emitted above).
	verifyKids := make([]string, 0, len(j.verifyKeys))
	for kid := range j.verifyKeys {
		if kid == keyID {
			continue
		}
		verifyKids = append(verifyKids, kid)
	}
	// Snapshot the matching public keys while still under keyMu.
	local := make(map[string]ed25519.PublicKey, len(verifyKids))
	for _, kid := range verifyKids {
		local[kid] = j.verifyKeys[kid]
	}
	j.keyMu.RUnlock()

	// Sort for deterministic output — the JWKS ETag depends on it.
	sortStrings(verifyKids)
	for _, kid := range verifyKids {
		out = append(out, sso.JWK{
			Kty: jwkKtyOKP,
			Crv: jwkCrvEd25519,
			Kid: kid,
			X:   base64.RawURLEncoding.EncodeToString(local[kid]),
			Use: jwkUseSig,
			Alg: jwtAlgEdDSA,
		})
	}

	// Adopted peer keys under a SEPARATE lock — keyMu is already released.
	j.peerKeysMu.RLock()
	peerKids := make([]string, 0, len(j.peerVerifyKeys))
	for kid := range j.peerVerifyKeys {
		peerKids = append(peerKids, kid)
	}
	peer := make(map[string]ed25519.PublicKey, len(peerKids))
	for _, kid := range peerKids {
		peer[kid] = j.peerVerifyKeys[kid]
	}
	j.peerKeysMu.RUnlock()

	sortStrings(peerKids)
	for _, kid := range peerKids {
		out = append(out, sso.JWK{
			Kty: jwkKtyOKP,
			Crv: jwkCrvEd25519,
			Kid: kid,
			X:   base64.RawURLEncoding.EncodeToString(peer[kid]),
			Use: jwkUseSig,
			Alg: jwtAlgEdDSA,
		})
	}
	return out, nil
}

// sortStrings is a tiny non-allocating bubble sort to avoid
// importing "sort" just for one ordering site. n is bounded by the
// number of retired keys an operator carries — typically 1, almost
// never more than a handful.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func jwtSigningInput(header ed25519Header, payload ed25519Payload) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	return []byte(encoded), nil
}

// fingerprintKid derives a deterministic kid from the public key — first 16
// hex chars of sha256(pubkey). Same key always yields the same kid.
func fingerprintKid(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// Compile-time check: the same issuer can mint OIDC ID Tokens, so
// operators don't need a second key + JWKS entry.
var _ oidc.IDTokenIssuer = (*Ed25519JWTIssuer)(nil)

// Compile-time check: same key also mints OIDC Back-Channel
// Logout tokens.
var _ sso.LogoutTokenIssuer = (*Ed25519JWTIssuer)(nil)

// The compile-time check that this issuer satisfies caep.JWTSigner lives
// in the caep package's test (caep/jwtsigner_guard_test.go), NOT here:
// defaultimpl is the foundational signing primitive and must not import
// the peripheral caep subsystem (a backwards edge + future-cycle risk).
// Go's structural typing means SignJWT below already satisfies
// caep.JWTSigner without a guard in this package.

// SignJWT signs an arbitrary claims object as a compact JWS using the
// SAME Ed25519 key (and kid) as access + ID + logout tokens, stamping
// the supplied `typ` in the JOSE header. It is the generic-JWT seam the
// CAEP/SSF transmitter reuses to mint Security Event Tokens (RFC 8417,
// `typ: secevent+jwt`) without going through the access-token Issue path
// (which would stamp `typ: at+jwt` and an access-token claim shape).
// Because the signing key is the one already published in JWKS, an RP
// validates a SET with no new trust setup.
//
// claims is marshalled as-is — the caller owns the full payload shape
// (iss, jti, iat, aud, sub_id, events). No claim is injected here, so
// this method makes no policy decisions and stays a pure signing
// primitive. typ MUST be non-empty (an unset typ would let a SET be
// mistaken for another JWT shape on the wire).
func (j *Ed25519JWTIssuer) SignJWT(ctx context.Context, typ string, claims any) (string, error) {
	if typ == "" {
		return "", errors.New("ed25519: sign jwt requires a typ header")
	}
	sgn, kid := j.currentKey()
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: typ, Kid: kid}
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
		return "", fmt.Errorf("ed25519: sign jwt (typ=%s): %w", typ, err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// AcceptsTokenFormat implements sso.TokenFormatHinter. A compact JWS
// has exactly two `.` separators between three non-empty base64url
// segments — anything else can't possibly be a JWT this issuer
// minted, so the multi-issuer dispatcher skips us and saves the
// base64 + signature parse cost. Tokens that happen to contain
// two dots but aren't JWTs still reach Validate, where the strict
// alg + typ allowlist + signature check rejects them.
func (j *Ed25519JWTIssuer) AcceptsTokenFormat(token string) bool {
	if token == "" {
		return false
	}
	// Fast count via strings.Count without splitting.
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

var _ sso.TokenFormatHinter = (*Ed25519JWTIssuer)(nil)

// logoutTokenTyp is OIDC BCL 1.0 §2.4's REQUIRED `typ` header.
const logoutTokenTyp = "logout+jwt"

// backchannelLogoutEvent is the URI used as the key inside the
// `events` claim per OIDC BCL §2.4. Value is an empty object —
// the spec says "any non-null value MAY be used; this
// specification uses the empty JSON object {} ".
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// ed25519LogoutPayload is the BCL §2.4 claim set. `events` is a
// map[string]json.RawMessage so the conventional empty-object
// value (`{}`) marshals cleanly.
type ed25519LogoutPayload struct {
	Iss    string                     `json:"iss,omitempty"`
	Sub    string                     `json:"sub,omitempty"`
	Aud    string                     `json:"aud,omitempty"`
	Iat    int64                      `json:"iat,omitempty"`
	Exp    int64                      `json:"exp,omitempty"`
	JTI    string                     `json:"jti,omitempty"`
	Events map[string]json.RawMessage `json:"events,omitempty"`
	// `nonce` is intentionally omitted — OIDC BCL §2.4 forbids
	// it. `sid` is populated when the caller passes a session id
	// via LogoutTokenRequest.SID — RPs use it to invalidate the
	// specific session they received the matching id_token for,
	// rather than wiping every session for the subject.
	SID string `json:"sid,omitempty"`
}

// DefaultLogoutTokenTTL bounds the logout-token lifetime. Short
// (60s) per OIDC BCL §2.4 — the RP processes the notification on
// receipt; a stale logout token has no use.
const DefaultLogoutTokenTTL = 60 * time.Second

// IssueLogoutToken mints a Back-Channel Logout token per OIDC
// BCL 1.0 §2.4. Same signing key, same kid, same JWKS entry as
// access + ID tokens — RPs verify all three with one key
// lookup.
func (j *Ed25519JWTIssuer) IssueLogoutToken(ctx context.Context, req *sso.LogoutTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("ed25519: logout token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultLogoutTokenTTL
	}
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("ed25519: generate jti: %w", err)
	}
	now := time.Now()
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: logoutTokenTyp, Kid: kid}
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
		return "", fmt.Errorf("ed25519: sign logout token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
