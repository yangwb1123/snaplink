package rs

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

// dpopProofMaxAgeDefault bounds how far in the past a proof iat may lie —
// the conventional RFC 9449 / FAPI 2.0 value, matching the AS default.
const dpopProofMaxAgeDefault = 60 * time.Second

// dpopReplayCapDefault bounds the jti replay cache. At the default 60s
// acceptance window this holds ~68 proofs/second of sustained traffic; a
// deployment beyond that should raise the cap via NewDPoPVerifier's verifier
// (the bound exists so an attacker spraying random jtis cannot grow RS
// memory without limit).
const dpopReplayCapDefault = 4096

// DPoPVerifier tunes RFC 9449 proof verification. The zero value works: the
// jti replay cache is created lazily and ProofMaxAge falls back to 60s.
//
// One verifier = one replay domain. Config.DPoPVerifier == nil selects a
// package-wide default so every validation in the process shares a single
// jti cache — separate caches would let one proof be replayed once per
// Config value.
type DPoPVerifier struct {
	// ProofMaxAge bounds how far in the past a proof iat may be; <=0
	// selects the 60s default.
	ProofMaxAge time.Duration

	once   sync.Once
	replay *dpopReplayCache
}

// NewDPoPVerifier constructs a verifier with its own bounded replay cache.
func NewDPoPVerifier() *DPoPVerifier { return &DPoPVerifier{} }

func (v *DPoPVerifier) cache() *dpopReplayCache {
	v.once.Do(func() {
		if v.replay == nil {
			v.replay = newDPoPReplayCache(dpopReplayCapDefault)
		}
	})
	return v.replay
}

func (v *DPoPVerifier) maxAge() time.Duration {
	if v.ProofMaxAge > 0 {
		return v.ProofMaxAge
	}
	return dpopProofMaxAgeDefault
}

// defaultDPoPVerifier backs Config.DPoPVerifier == nil (see DPoPVerifier).
var defaultDPoPVerifier = NewDPoPVerifier()

func (c Config) dpopVerifier() *DPoPVerifier {
	if c.DPoPVerifier != nil {
		return c.DPoPVerifier
	}
	return defaultDPoPVerifier
}

// ValidateTokenWithDPoP validates the access token (local or introspection
// mode per Config) and then enforces the RFC 9449 §7.1 resource-server
// checks: the token MUST be cnf.jkt-bound, and the proof MUST verify, bind
// this exact request (htm/htu), be fresh (iat window), be first-use (jti
// replay cache), hash-bind this exact token (ath), and be signed by the key
// the token is constrained to (thumbprint == cnf.jkt).
func ValidateTokenWithDPoP(ctx context.Context, token, dpopProof, htm, htu string, cfg Config) (*Claims, error) {
	claims, err := validateByMode(ctx, token, cfg)
	if err != nil {
		return nil, err
	}
	if claims.CnfJKT == "" {
		// A bearer token cannot become sender-constrained after the fact;
		// accepting it here would silently downgrade the caller's DPoP
		// expectation.
		return nil, fmt.Errorf("%w: token carries no cnf.jkt binding", ErrDPoPInvalid)
	}
	if err := verifyDPoPProof(dpopProof, htm, htu, token, claims.CnfJKT, cfg); err != nil {
		return nil, err
	}
	return claims, nil
}

// verifyDPoPProof mirrors the AS-side gate ladder: header+jwk parse -> JWS
// verify -> request binding (htm/htu/iat/jti/ath) -> jti replay -> cnf.jkt
// thumbprint. Each step fails closed with a DPoP-shaped error.
func verifyDPoPProof(proof, htm, htu, accessToken, wantJKT string, cfg Config) error {
	jwk, err := parseDPoPProofHeader(proof)
	if err != nil {
		return err
	}
	// The proof carries its OWN ephemeral key in the header jwk; verifying
	// with the shared primitive keeps the alg-confusion defenses (allowlist
	// before signature, kty/crv<->alg consistency, EC on-curve, RSA>=2048).
	if _, err := security.VerifyCompactJWS(proof, []core.JWK{jwk}, cfg.allowedAlgSet()); err != nil {
		return fmt.Errorf("%w: signature: %v", ErrDPoPInvalid, err)
	}
	verifier := cfg.dpopVerifier()
	p, err := parseDPoPProofPayload(proof)
	if err != nil {
		return err
	}
	if err := checkDPoPProofClaims(p, htm, htu, accessToken, cfg.skew(), verifier.maxAge()); err != nil {
		return err
	}
	// Remember the jti until iat+maxAge — the LATEST instant the iat window
	// still accepts this proof — so the replay horizon and the acceptance
	// horizon expire together (mirrors the AS-side anchoring).
	now := time.Now().Unix()
	if !verifier.cache().markSeen(p.JTI, p.IAT+int64(verifier.maxAge().Seconds()), now) {
		return fmt.Errorf("%w: jti %q", ErrDPoPReplayed, p.JTI)
	}
	jkt, err := jwkThumbprintRFC7638(jwk)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDPoPInvalid, err)
	}
	if subtle.ConstantTimeCompare([]byte(jkt), []byte(wantJKT)) != 1 {
		return fmt.Errorf("%w: proof key thumbprint does not match token cnf.jkt", ErrDPoPInvalid)
	}
	return nil
}

// parseDPoPProofHeader decodes the first proof segment, enforces the RFC
// 9449 typ, and projects the embedded jwk down to its PUBLIC members only —
// a proof can never smuggle extra key material toward the verifier or the
// thumbprint.
func parseDPoPProofHeader(proof string) (core.JWK, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 || parts[2] == "" {
		return core.JWK{}, fmt.Errorf("%w: not a compact JWS", ErrDPoPInvalid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return core.JWK{}, fmt.Errorf("%w: header decode: %v", ErrDPoPInvalid, err)
	}
	var h struct {
		Typ string          `json:"typ"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return core.JWK{}, fmt.Errorf("%w: header parse: %v", ErrDPoPInvalid, err)
	}
	if !strings.EqualFold(h.Typ, dpopProofTyp) {
		return core.JWK{}, fmt.Errorf("%w: typ %q", ErrDPoPInvalid, h.Typ)
	}
	if len(h.JWK) == 0 {
		return core.JWK{}, fmt.Errorf("%w: header missing jwk", ErrDPoPInvalid)
	}
	return parseProofJWK(h.JWK)
}

// parseProofJWK keeps only the public members each key type needs; a
// type-specific presence check gives a DPoP-shaped error before the shared
// verifier runs.
func parseProofJWK(raw json.RawMessage) (core.JWK, error) {
	var j struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		return core.JWK{}, fmt.Errorf("%w: jwk parse: %v", ErrDPoPInvalid, err)
	}
	switch j.Kty {
	case "OKP":
		if j.Crv == "" || j.X == "" {
			return core.JWK{}, fmt.Errorf("%w: OKP jwk missing crv/x", ErrDPoPInvalid)
		}
		return core.JWK{Kty: "OKP", Crv: j.Crv, X: j.X}, nil
	case "EC":
		if j.Crv == "" || j.X == "" || j.Y == "" {
			return core.JWK{}, fmt.Errorf("%w: EC jwk missing crv/x/y", ErrDPoPInvalid)
		}
		return core.JWK{Kty: "EC", Crv: j.Crv, X: j.X, Y: j.Y}, nil
	case "RSA":
		if j.N == "" || j.E == "" {
			return core.JWK{}, fmt.Errorf("%w: RSA jwk missing n/e", ErrDPoPInvalid)
		}
		return core.JWK{Kty: "RSA", N: j.N, E: j.E}, nil
	default:
		return core.JWK{}, fmt.Errorf("%w: unsupported jwk kty %q", ErrDPoPInvalid, j.Kty)
	}
}

// dpopProofClaims mirrors the RFC 9449 §4.2 claims bound to the request.
type dpopProofClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	JTI string `json:"jti"`
	Ath string `json:"ath"`
}

func parseDPoPProofPayload(proof string) (dpopProofClaims, error) {
	parts := strings.Split(proof, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return dpopProofClaims{}, fmt.Errorf("%w: payload decode: %v", ErrDPoPInvalid, err)
	}
	var p dpopProofClaims
	if err := json.Unmarshal(raw, &p); err != nil {
		return dpopProofClaims{}, fmt.Errorf("%w: payload parse: %v", ErrDPoPInvalid, err)
	}
	return p, nil
}

// checkDPoPProofClaims binds the proof to the live request. ath is REQUIRED
// here (unlike at the /token endpoint, where no token exists yet): RFC 9449
// §4.3 (11) — at a protected resource the proof must hash-bind the exact
// access token presented, or a proof stolen alongside a DIFFERENT token of
// the same key could be replayed.
func checkDPoPProofClaims(p dpopProofClaims, htm, htu, accessToken string, skew, maxAge time.Duration) error {
	if !strings.EqualFold(p.HTM, htm) {
		return fmt.Errorf("%w: htm %q != request method %q", ErrDPoPInvalid, p.HTM, htm)
	}
	if normalizeHTU(p.HTU) != normalizeHTU(htu) {
		return fmt.Errorf("%w: htu %q != request url %q", ErrDPoPInvalid, p.HTU, htu)
	}
	if err := checkDPoPIatWindow(p.IAT, skew, maxAge); err != nil {
		return err
	}
	if p.JTI == "" {
		return fmt.Errorf("%w: missing jti", ErrDPoPInvalid)
	}
	sum := sha256.Sum256([]byte(accessToken))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(p.Ath), []byte(want)) != 1 {
		return fmt.Errorf("%w: ath does not bind the presented access token", ErrDPoPInvalid)
	}
	return nil
}

func checkDPoPIatWindow(iat int64, skew, maxAge time.Duration) error {
	if iat == 0 {
		return fmt.Errorf("%w: missing iat", ErrDPoPInvalid)
	}
	now := time.Now().Unix()
	if iat > now+int64(skew.Seconds()) {
		return fmt.Errorf("%w: iat in the future beyond clock skew", ErrDPoPInvalid)
	}
	if iat < now-int64(maxAge.Seconds()) {
		return fmt.Errorf("%w: proof too old", ErrDPoPInvalid)
	}
	return nil
}

// normalizeHTU strips query + fragment per RFC 9449 §4.3: htu comparison
// covers scheme://host/path only.
func normalizeHTU(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// jwkThumbprintRFC7638 computes the RFC 7638 §3 thumbprint: base64url SHA-256
// of the canonical JSON of the REQUIRED members for the key type, lexically
// ordered, no whitespace. The string is assembled directly (not via
// json.Marshal) so member ORDER is guaranteed; a wrong member set yields a
// different thumbprint, and for DPoP a wrong thumbprint is a binding bypass.
// (Local minimal copy: the AS-side helper is unexported in interfaces/sso,
// which this dependency-light SDK deliberately does not import.)
func jwkThumbprintRFC7638(jwk core.JWK) (string, error) {
	var canonical string
	switch jwk.Kty {
	case "OKP":
		canonical = `{"crv":"` + jwk.Crv + `","kty":"OKP","x":"` + jwk.X + `"}`
	case "EC":
		canonical = `{"crv":"` + jwk.Crv + `","kty":"EC","x":"` + jwk.X + `","y":"` + jwk.Y + `"}`
	case "RSA":
		canonical = `{"e":"` + jwk.E + `","kty":"RSA","n":"` + jwk.N + `"}`
	default:
		return "", fmt.Errorf("unsupported jwk kty %q for thumbprint", jwk.Kty)
	}
	h := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// dpopReplayCache is a bounded first-use tracker for proof jtis. Expired
// entries are dropped lazily; at capacity the entry closest to expiry is
// evicted first, so forced eviction costs at most the tail of one proof's
// acceptance window rather than unbounded RS memory.
type dpopReplayCache struct {
	mu       sync.Mutex
	capacity int
	seen     map[string]int64 // jti -> unix expiry
}

func newDPoPReplayCache(capacity int) *dpopReplayCache {
	return &dpopReplayCache{capacity: capacity, seen: make(map[string]int64, 64)}
}

// markSeen records jti until expiry; false means it was already recorded and
// has not yet expired (a replay).
func (c *dpopReplayCache) markSeen(jti string, expiry, now int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[jti]; ok && exp > now {
		return false
	}
	if len(c.seen) >= c.capacity {
		c.evictLocked(now)
	}
	c.seen[jti] = expiry
	return true
}

// evictLocked drops expired entries, then — only if still at capacity —
// the soonest-to-expire live entry.
func (c *dpopReplayCache) evictLocked(now int64) {
	for k, exp := range c.seen {
		if exp <= now {
			delete(c.seen, k)
		}
	}
	for len(c.seen) >= c.capacity {
		var victim string
		var soonest int64
		for k, exp := range c.seen {
			if victim == "" || exp < soonest {
				victim, soonest = k, exp
			}
		}
		delete(c.seen, victim)
	}
}
