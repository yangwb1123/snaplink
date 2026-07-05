package defaultimpl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oidc"
)

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
	return signCompactJWS(ctx, sgn, header, claims, "ecdsa: sign claims")
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
// Alg reports the JWS alg this issuer signs with, so callers (e.g. the userinfo
// signing gate) can confirm a client's requested signed-response alg matches
// what this issuer actually produces. This issuer signs ES256 exclusively.
func (j *ECDSAJWTIssuer) Alg() string { return jwtAlgES256 }

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
	// RFC 7518 §6.2 requires the affine coordinates split out as separate
	// base64url members; only PublicKey.X/.Y expose them. We read (never
	// mutate) the raw values, so the deprecation's invalid-key hazard does
	// not apply.
	pub.X.FillBytes(xb) //nolint:staticcheck // raw EC coords required for JWK X/Y encoding
	pub.Y.FillBytes(yb) //nolint:staticcheck // raw EC coords required for JWK X/Y encoding
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

// ecdsaFingerprintKid derives a deterministic kid from the P-256 public
// key — first 8 bytes of sha256 over the SEC1 uncompressed point,
// base64url-encoded. Same key always yields the same kid (so replicas
// sharing a key agree on JWKS lookups).
func ecdsaFingerprintKid(pub *ecdsa.PublicKey) string {
	point := elliptic.Marshal(pub.Curve, pub.X, pub.Y) //nolint:staticcheck // SEC1 point is the stable kid input across Go versions
	sum := sha256.Sum256(point)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// Compile-time interface guards. The caep.JWTSigner guard is deliberately
// NOT here: it lives in caep/jwtsigner_guard_test.go so the foundational
// defaultimpl package never imports the peripheral caep subsystem. SignJWT
// satisfies caep.JWTSigner structurally regardless.
var (
	_ sso.TokenIssuer       = (*ECDSAJWTIssuer)(nil)
	_ oidc.IDTokenIssuer    = (*ECDSAJWTIssuer)(nil)
	_ oidc.UserinfoSigner   = (*ECDSAJWTIssuer)(nil)
	_ oidc.MetadataSigner   = (*ECDSAJWTIssuer)(nil)
	_ sso.LogoutTokenIssuer = (*ECDSAJWTIssuer)(nil)
	_ sso.TokenFormatHinter = (*ECDSAJWTIssuer)(nil)
	_ sso.JWKSProvider      = (*ECDSAJWTIssuer)(nil)
)
