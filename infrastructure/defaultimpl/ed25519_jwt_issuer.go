package defaultimpl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/core"
)

// metricsAlgEdDSA is this family's bounded sso_signing_key_usage_total alg
// label, matching cmd/sso-server/serverbuildsign.normalizeAlgLabel's
// vocabulary so the external-signer and in-process metrics agree on alg
// spelling.
const metricsAlgEdDSA = "eddsa"

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

	// revoked is the in-process revocation deny-set, keyed by the FULL token
	// and valued by the token's `exp` (unix seconds). It is consulted in
	// Validate (presence ⇒ rejected) and added to in Revoke. Keying by exp
	// lets Revoke lazily prune entries whose exp has already passed (Validate
	// rejects those on expiry anyway), bounding the map — see revocation_set.go.
	revokedMu sync.RWMutex
	revoked   map[string]int64
	// revocationStore is the OPTIONAL durable backing for `revoked` (nil =
	// in-process only). Revoke persists to it; SeedRevocations re-seeds
	// `revoked` from it at boot so a revocation survives a restart.
	revocationStore RevocationStore

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

	// keyOrigin is the HSM/software attestation for this issuer's signing
	// key. Defaults to OriginUnattested (software). Set via
	// WithEd25519KeyOrigin when the key is backed by an HSM/KMS.
	keyOrigin core.KeyOrigin

	// clock is nil by default (nowFrom falls back to time.Now()) — see
	// WithEd25519Clock.
	clock Clock

	// metrics records per-(alg,kid) signing usage (see recordSigningUsage).
	// nil (the default) when WithEd25519Metrics isn't wired — every call is a
	// no-op, matching every other optional metric in this codebase.
	metrics *metrics.Metrics
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

// WithEd25519KeyFile persists the Ed25519 signing key to a PEM file
// (PKCS#8) so a process restart reuses the same key (kid stable across
// restarts — the deployed `rotation.enabled=false` profile otherwise
// regenerates the key on every boot and silently invalidates every
// issued token). First run: generate + write (0600, atomic rename).
// Subsequent runs: load. External signer wins when both are set.
func WithEd25519KeyFile(path string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		if j.signer != nil || path == "" {
			return
		}
		priv, err := loadOrGenerateEd25519Key(path)
		if err != nil {
			panic(fmt.Sprintf("ed25519: key file %s: %v", path, err))
		}
		j.privateKey = priv
		j.publicKey = priv.Public().(ed25519.PublicKey)
	}
}

func loadOrGenerateEd25519Key(path string) (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("decode PEM")
		}
		der, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8: %w", err)
		}
		priv, ok := der.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an Ed25519 key")
		}
		return priv, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pemBytes, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return priv, nil
}

// WithEd25519KeyID overrides the auto-derived kid.
func WithEd25519KeyID(kid string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.keyID = kid }
}

// WithEd25519Clock overrides the wall clock Issue/IssueIDToken/
// IssueLogoutToken read for iat/nbf/exp. Test-only knob: nil (the
// default every issuer starts with) means every call reads the real
// time.Now(), byte-identical to the code before Clock existed. Wiring a
// fixed or steppable Clock lets a test assert exact claim values without
// sleeping or tolerating a timing window.
func WithEd25519Clock(c Clock) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.clock = c }
}

// WithEd25519Metrics wires per-(alg,kid) signing-usage observability
// (sso_signing_key_usage_total). Optional — a nil or omitted Metrics keeps
// every Sign call a no-op observation, byte-identical to a build without it.
func WithEd25519Metrics(m *metrics.Metrics) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.metrics = m }
}

// recordSigningUsage bumps the signing-usage counter for a successful
// in-process sign. Nil-safe; called from every Issue*/SignJWT method right
// after their sgn.Sign succeeds, never from JWKS/lookup paths that don't
// actually sign.
func (j *Ed25519JWTIssuer) recordSigningUsage(kid string) {
	j.metrics.ObserveSigningUsage(metricsAlgEdDSA, kid)
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
		revoked:  make(map[string]int64),
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

// WithEd25519KeyOrigin sets the key origin attestation for this issuer's
// signing key. Defaults to OriginUnattested (software). Callers that wire
// a KMS/HSM-backed external signer SHOULD set this to the appropriate
// value so the JWKS endpoint publishes the origin for compliance audits.
func WithEd25519KeyOrigin(origin core.KeyOrigin) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.keyOrigin = origin }
}

// KeyOrigin returns the key origin attestation for this issuer's signing
// key. Implements core.KeyOriginProvider.
func (j *Ed25519JWTIssuer) KeyOrigin(_ context.Context, kid string) (core.KeyOrigin, error) {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	if kid != "" && kid != j.keyID {
		return core.OriginUnknown, nil
	}
	return j.keyOrigin, nil
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

// RotateNow is the alg-uniform runtime-rotation seam the admin API drives:
// it generates a fresh key and promotes it (demoting the current key to
// verify-only), returning the new kid. RotateKey's signature is alg-specific
// (it takes an *ed25519* private key), so no shared interface can call it —
// RotateNow gives all three built-in issuers one nullary shape the cmd
// orchestration closure can assert on structurally.
func (j *Ed25519JWTIssuer) RotateNow() (string, error) { return j.RotateKey(nil) }

// ScheduleRetire drops kid after `after`, arranging the SAME grace-delayed
// overlap-window retire the scheduled loop does via scheduleRetire. Bound to
// a background context (the process lifetime): a runtime admin rotate has no
// request-scoped ctx to outlive the grace window, and a leaked timer here is
// fail-safe — it can only ever KEEP a demoted key verifiable longer, never
// retire it early. after<=0 keeps the demoted key until a manual RetireKey.
func (j *Ed25519JWTIssuer) ScheduleRetire(kid string, after time.Duration) {
	j.scheduleRetire(context.Background(), kid, after)
}
