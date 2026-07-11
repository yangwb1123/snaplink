package defaultimpl

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

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

	h, err := j.parseAndGuardHeader(parts[0])
	if err != nil {
		return nil, err
	}
	if err := j.verifyRSASignature(h, parts); err != nil {
		return nil, err
	}
	p, err := j.decodeAndCheckClaims(parts[1])
	if err != nil {
		return nil, err
	}
	return claimsFromPayload(p), nil
}

// parseAndGuardHeader base64-decodes + JSON-parses the JWS header and enforces
// the strict alg match + typ allowlist.
//
// RFC 9068 §4: enforce alg + typ BEFORE signature verification. This
// issuer accepts ONLY its configured alg (RS256 xor PS256), so a token
// minted with the other RSA padding — or EdDSA / ES256 / `none` — is
// rejected here, never reaching the verify path. Strict kid->alg: the
// RP can't pick the verification algorithm.
func (j *RSAJWTIssuer) parseAndGuardHeader(headerB64 string) (rsaHeader, error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return rsaHeader{}, fmt.Errorf("rsa: header decode: %w", err)
	}
	var h rsaHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return rsaHeader{}, fmt.Errorf("rsa: header parse: %w", err)
	}
	if h.Alg != j.alg {
		return rsaHeader{}, fmt.Errorf("rsa: alg %q not accepted (issuer signs %q)", h.Alg, j.alg)
	}
	if h.Typ != "" {
		if _, ok := supportedJWTTypes[h.Typ]; !ok {
			return rsaHeader{}, fmt.Errorf("rsa: typ %q not in allowlist", h.Typ)
		}
	}
	return h, nil
}

// verifyRSASignature decodes the signature segment, looks up the verify key by
// kid, and runs the RS256/PS256 verify (threaded j.alg so the PSS/PKCS1v15
// selection is unchanged) over the signing input.
func (j *RSAJWTIssuer) verifyRSASignature(h rsaHeader, parts []string) error {
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("rsa: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]

	pub := j.lookupVerifyKey(h.Kid)
	if pub == nil {
		return errors.New("rsa: unknown kid")
	}
	if !rsaVerifyJWS(pub, []byte(signingInput), sig, j.alg) {
		return errors.New("rsa: signature invalid")
	}
	return nil
}

// decodeAndCheckClaims base64-decodes + JSON-parses the payload and enforces
// exp/nbf against the issuer's clock skew.
func (j *RSAJWTIssuer) decodeAndCheckClaims(payloadB64 string) (ed25519Payload, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return ed25519Payload{}, fmt.Errorf("rsa: payload decode: %w", err)
	}
	var p ed25519Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return ed25519Payload{}, fmt.Errorf("rsa: payload parse: %w", err)
	}

	// Stored JWT timestamps (Exp/Nbf) are Unix integers from external issuers;
	// time.Unix() produces wall-clock times only. Monotonic safety cannot
	// apply here — cross-process timestamps never carry a monotonic component.
	if p.Exp != 0 && time.Since(time.Unix(p.Exp, 0)) >= j.maxClockSkew {
		return ed25519Payload{}, errors.New("rsa: token expired")
	}
	if p.Nbf != 0 && time.Until(time.Unix(p.Nbf, 0)) > j.maxClockSkew {
		return ed25519Payload{}, errors.New("rsa: token not yet valid")
	}
	return p, nil
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
// RevocationStore at boot (and on live invalidation-bus recovery) so a
// pre-restart / missed revocation is honored again. nil store = no-op; the
// store Load runs unlocked so a live replica's Validate is never stalled behind
// store I/O. See RevocationStore / seedRevokedFromStore.
func (j *RSAJWTIssuer) SeedRevocations(ctx context.Context) error {
	return seedRevokedFromStore(ctx, &j.revokedMu, j.revoked, j.revocationStore)
}

// WithRSARevocationStore wires a durable RevocationStore (restart-survival;
// call SeedRevocations after construction). nil = in-process only.
func WithRSARevocationStore(store RevocationStore) RSAOption {
	return func(j *RSAJWTIssuer) { j.revocationStore = store }
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
