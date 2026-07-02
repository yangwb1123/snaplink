package defaultimpl

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
)

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
	return j.signClaims(ctx, sgn, kid, jwtTyp, claims)
}

// SignMetadata implements [oidc.MetadataSigner]. Wraps the discovery
// document claims in a JWS using the same key as access + ID +
// userinfo tokens. Header includes `kid` so an RP that's already
// fetched JWKS can pick the right key for verification.
func (j *Ed25519JWTIssuer) SignMetadata(ctx context.Context, claims map[string]any) (string, error) {
	if claims == nil {
		return "", nil
	}
	sgn, kid := j.currentKey()
	return j.signClaims(ctx, sgn, kid, jwtTyp, claims)
}

// SignIntrospectionJWT implements [oauth.IntrospectionSigner] — RFC 9701
// JWT-formatted /token/introspect responses. Deployments MUST point this
// at a DEDICATED Ed25519JWTIssuer instance (its own key), never the
// access/ID-token issuer — see oauth.IntrospectionSigner. The typ header
// is core.JWTTypIntrospection, distinct from the generic "JWT" typ
// SignUserInfo/SignMetadata use, per the RFC's substitution-attack
// defense (§8): an RS checking typ can never mistake this JWT for a
// bearer access token.
func (j *Ed25519JWTIssuer) SignIntrospectionJWT(ctx context.Context, claims map[string]any) (string, error) {
	if claims == nil {
		return "", nil
	}
	sgn, kid := j.currentKey()
	return j.signClaims(ctx, sgn, kid, core.JWTTypIntrospection, claims)
}

// signClaims is the shared JWS assembler for the free-form claim-map
// signers (userinfo, metadata, introspection) — mirrors the ECDSA/RSA
// issuers' helper of the same name/shape.
func (j *Ed25519JWTIssuer) signClaims(ctx context.Context, sgn Ed25519Signer, kid, typ string, claims map[string]any) (string, error) {
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
		return "", fmt.Errorf("ed25519: sign claims: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
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
// Alg reports the JWS alg this issuer signs with, so callers (e.g. the userinfo
// signing gate) can confirm a client's requested signed-response alg matches
// what this issuer actually produces. Ed25519 signs EdDSA exclusively.
func (j *Ed25519JWTIssuer) Alg() string { return jwtAlgEdDSA }

func (j *Ed25519JWTIssuer) JWKS(_ context.Context) ([]sso.JWK, error) {
	j.keyMu.RLock()
	keyID := j.keyID
	out := []sso.JWK{ed25519PublicJWK(keyID, j.publicKey)}
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
		out = append(out, ed25519PublicJWK(kid, local[kid]))
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
		out = append(out, ed25519PublicJWK(kid, peer[kid]))
	}
	return out, nil
}

// ed25519PublicJWK builds the RFC 8037 §2 OKP JWK for an Ed25519 public
// key: kty "OKP", crv "Ed25519", x = base64url(raw 32-byte public key).
func ed25519PublicJWK(kid string, pub ed25519.PublicKey) sso.JWK {
	return sso.JWK{
		Kty: jwkKtyOKP,
		Crv: jwkCrvEd25519,
		Kid: kid,
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Use: jwkUseSig,
		Alg: jwtAlgEdDSA,
	}
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

// Compile-time check: an Ed25519JWTIssuer instance (a DEDICATED one, per
// oauth.IntrospectionSigner's doc) can sign RFC 9701 introspection JWTs.
var _ oauth.IntrospectionSigner = (*Ed25519JWTIssuer)(nil)
