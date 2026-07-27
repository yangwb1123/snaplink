package defaultimpl

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
)

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

// SignIntrospectionJWT implements [oauth.IntrospectionSigner] — RFC 9701
// JWT-formatted /token/introspect responses. Deployments MUST point this
// at a DEDICATED RSAJWTIssuer instance (its own key), never the
// access/ID-token issuer — see oauth.IntrospectionSigner. The typ header
// is core.JWTTypIntrospection, distinct from the generic "JWT" typ
// SignUserInfo/SignMetadata use, per the RFC's substitution-attack
// defense (§8): an RS checking typ can never mistake this JWT for a
// bearer access token.
func (j *RSAJWTIssuer) SignIntrospectionJWT(ctx context.Context, claims map[string]any) (string, error) {
	if claims == nil {
		return "", nil
	}
	sgn, kid := j.currentKey()
	return j.signClaims(ctx, sgn, kid, core.JWTTypIntrospection, claims)
}

// signClaims is the shared JWS assembler for the free-form claim-map
// signers (userinfo, metadata, introspection).
func (j *RSAJWTIssuer) signClaims(ctx context.Context, sgn RSASigner, kid, typ string, claims map[string]any) (string, error) {
	header := rsaHeader{Alg: j.alg, Typ: typ, Kid: kid}
	return signCompactJWS(ctx, sgn, header, claims, "rsa: sign claims")
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
// Alg reports the JWS alg this issuer signs with, so callers (e.g. the userinfo
// signing gate) can confirm a client's requested signed-response alg matches
// what this issuer actually produces (RS256 or PS256, fixed at construction).
func (j *RSAJWTIssuer) Alg() string { return j.alg }

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
	stampKeyOrigin(out, j.keyOrigin)
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

// Compile-time interface guards. The caep.JWTSigner guard is deliberately
// NOT here: it lives in caep/jwtsigner_guard_test.go so the foundational
// defaultimpl package never imports the peripheral caep subsystem. SignJWT
// satisfies caep.JWTSigner structurally regardless.
var (
	_ sso.TokenIssuer           = (*RSAJWTIssuer)(nil)
	_ oidc.IDTokenIssuer        = (*RSAJWTIssuer)(nil)
	_ oidc.UserinfoSigner       = (*RSAJWTIssuer)(nil)
	_ oidc.MetadataSigner       = (*RSAJWTIssuer)(nil)
	_ sso.LogoutTokenIssuer     = (*RSAJWTIssuer)(nil)
	_ sso.TokenFormatHinter     = (*RSAJWTIssuer)(nil)
	_ sso.JWKSProvider          = (*RSAJWTIssuer)(nil)
	_ oauth.IntrospectionSigner = (*RSAJWTIssuer)(nil)
	_ core.KeyOriginProvider    = (*RSAJWTIssuer)(nil)
)
