package defaultimpl

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/snaplink/sso"
)

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
	if len(p.RequestedClaims) > 0 {
		claims.RequestedClaims = append(json.RawMessage(nil), p.RequestedClaims...)
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

// Revoke adds the token to the in-memory, exp-bounded deny list. Returns an
// error when the token wasn't signed by this issuer, so revokeAcrossIssuers
// correctly attributes ownership. Keyed by the token's `exp` so markRevoked
// can lazily prune past-exp entries (prune-not-early; see revocation_set.go).
func (j *ECDSAJWTIssuer) Revoke(ctx context.Context, token string) error {
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
func (j *ECDSAJWTIssuer) SeedRevocations(ctx context.Context) error {
	if j.revocationStore == nil {
		return nil
	}
	j.revokedMu.Lock()
	defer j.revokedMu.Unlock()
	return seedRevokedFromStore(ctx, j.revoked, j.revocationStore)
}

// WithECDSARevocationStore wires a durable RevocationStore (restart-survival;
// call SeedRevocations after construction). nil = in-process only.
func WithECDSARevocationStore(store RevocationStore) ECDSAOption {
	return func(j *ECDSAJWTIssuer) { j.revocationStore = store }
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
