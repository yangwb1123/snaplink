package defaultimpl

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso"
)

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
	if len(p.RequestedClaims) > 0 {
		claims.RequestedClaims = append(json.RawMessage(nil), p.RequestedClaims...)
	}
	return claims, nil
}

// Revoke adds the token to an in-memory, exp-bounded deny list. Returns an
// error when the token wasn't signed by this issuer, so that
// revokeAcrossIssuers correctly attributes ownership.
//
// The entry is keyed by the token's `exp` (read back from the Validate call
// above, which already decoded the payload), so markRevoked can lazily prune
// entries whose exp has passed — Validate rejects an expired token on its own,
// making a past-exp deny-set entry redundant. NEVER prunes a still-valid entry
// (prune-not-early, see revocation_set.go).
func (j *Ed25519JWTIssuer) Revoke(ctx context.Context, token string) error {
	claims, err := j.Validate(ctx, token)
	if err != nil {
		return err
	}
	exp := claims.ExpiresAt.Unix()
	j.revokedMu.Lock()
	markRevoked(j.revoked, token, exp)
	store := j.revocationStore
	j.revokedMu.Unlock()
	// Persist for restart-survival, best-effort: the in-process revoke above
	// already took effect on this replica, so a store outage must NOT fail the
	// admin's revoke (a failed persist only loses durability across a restart,
	// not the live revocation). The caller's audit records the revoke itself.
	if store != nil {
		_ = store.Revoke(ctx, token, exp)
	}
	return nil
}

// SeedRevocations re-seeds the in-process revocation deny-set from the wired
// RevocationStore (if any). Call it once at boot AFTER construction so a
// revocation issued before a restart is honored again. nil store = no-op,
// idempotent, safe alongside Validate (takes the write lock); already-expired
// entries are skipped (prune-not-early).
func (j *Ed25519JWTIssuer) SeedRevocations(ctx context.Context) error {
	if j.revocationStore == nil {
		return nil
	}
	j.revokedMu.Lock()
	defer j.revokedMu.Unlock()
	return seedRevokedFromStore(ctx, j.revoked, j.revocationStore)
}

// WithEd25519RevocationStore wires a durable RevocationStore so access-token
// revocations survive a process restart (see RevocationStore). Call
// SeedRevocations after construction to re-seed the in-process deny-set.
// nil = in-process only (byte-identical to the historical behavior).
func WithEd25519RevocationStore(store RevocationStore) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.revocationStore = store }
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
