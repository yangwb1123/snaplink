package defaultimpl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// issueECPeerToken mints a token from a separate "peer" ES256 issuer and
// returns the token plus the peer's kid + public key (the material a real
// replica would publish to the shared signing-key registry).
func issueECPeerToken(t *testing.T) (token, peerKid string, peerPub *ecdsa.PublicKey) {
	t.Helper()
	peer := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAIssuer("peer-iss"),
		defaultimpl.WithECDSATokenTTL(5*time.Minute),
	)
	tok, err := peer.Issue(context.Background(), &sso.Subject{ID: "user-peer"}, []string{"read"})
	if err != nil {
		t.Fatalf("peer Issue: %v", err)
	}
	return tok.AccessToken, peer.KeyID(), peer.PublicKey()
}

// TestECDSAPeerKey_AdoptAppearsInJWKS proves an adopted EC peer key surfaces in
// JWKS as a verify-only (use:sig) EC entry under the peer's kid.
func TestECDSAPeerKey_AdoptAppearsInJWKS(t *testing.T) {
	local := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("local-iss"))
	_, peerKid, peerPub := issueECPeerToken(t)

	if err := local.AdoptVerifyKey(peerKid, peerPub); err != nil {
		t.Fatalf("AdoptVerifyKey: %v", err)
	}

	jwks, err := local.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var found *sso.JWK
	for i := range jwks {
		if jwks[i].Kid == peerKid {
			found = &jwks[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("peer kid %q not in JWKS %+v", peerKid, jwks)
	}
	if found.Use != "sig" {
		t.Errorf("peer JWK use = %q, want sig", found.Use)
	}
	if found.Alg != "ES256" || found.Kty != "EC" || found.Crv != "P-256" {
		t.Errorf("peer JWK shape wrong: %+v", found)
	}
	if found.X == "" || found.Y == "" {
		t.Errorf("peer EC JWK missing x/y: %+v", found)
	}
}

// TestECDSAPeerKey_AdoptedTokenValidates proves a token signed by a SEPARATE
// ES256 issuer validates on the local issuer after adoption — the core
// cross-replica verification property.
func TestECDSAPeerKey_AdoptedTokenValidates(t *testing.T) {
	local := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("local-iss"))
	token, peerKid, peerPub := issueECPeerToken(t)

	// Before adoption the local issuer can't verify the peer token (unknown
	// kid) — fail-closed.
	if _, err := local.Validate(context.Background(), token); err == nil {
		t.Fatal("expected peer token to fail validation before adoption")
	}

	if err := local.AdoptVerifyKey(peerKid, peerPub); err != nil {
		t.Fatalf("AdoptVerifyKey: %v", err)
	}
	claims, err := local.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate after adoption: %v", err)
	}
	if claims.Subject != "user-peer" {
		t.Errorf("Subject = %q, want user-peer", claims.Subject)
	}
}

// TestECDSAPeerKey_LocalRotationLeavesPeerKeys proves the local key lifecycle
// (RotateKey / RetireKey) never touches adopted peer keys — peer lifecycle is
// owned by the registry side, not local rotation.
func TestECDSAPeerKey_LocalRotationLeavesPeerKeys(t *testing.T) {
	local := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("local-iss"))
	token, peerKid, peerPub := issueECPeerToken(t)
	if err := local.AdoptVerifyKey(peerKid, peerPub); err != nil {
		t.Fatalf("AdoptVerifyKey: %v", err)
	}

	oldKID := local.KeyID()
	if _, err := local.RotateKey(nil); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if err := local.RetireKey(oldKID); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}

	jwks, err := local.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if !jwksHasKid(jwks, peerKid) {
		t.Fatalf("peer kid %q dropped by local rotation/retirement", peerKid)
	}
	if _, err := local.Validate(context.Background(), token); err != nil {
		t.Fatalf("peer token failed after local rotation: %v", err)
	}

	// DropVerifyKey removes ONLY the peer key.
	local.DropVerifyKey(peerKid)
	jwks, _ = local.JWKS(context.Background())
	if jwksHasKid(jwks, peerKid) {
		t.Fatalf("peer kid %q still present after DropVerifyKey", peerKid)
	}
}

// TestECDSAPeerKey_AlgConfusionRejected proves an ES256 peer token is rejected
// by an EdDSA issuer AND by an RS256 issuer: the alg gate runs BEFORE key
// lookup, so an adopted-or-not ES256 key can never be reached on a non-ES256
// verify path.
func TestECDSAPeerKey_AlgConfusionRejected(t *testing.T) {
	token, _, _ := issueECPeerToken(t)

	edIss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("ed-iss"))
	if _, err := edIss.Validate(context.Background(), token); err == nil {
		t.Fatal("EdDSA issuer accepted an ES256 token — alg gate breached")
	}

	rsIss := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAIssuer("rs-iss"))
	if _, err := rsIss.Validate(context.Background(), token); err == nil {
		t.Fatal("RS256 issuer accepted an ES256 token — alg gate breached")
	}
}

// TestECDSAPeerKey_CollisionGuard proves adoption refuses a kid that collides
// with the local active signing key, an empty kid, a nil key, and a key on the
// wrong curve (ES256 accepts only P-256).
func TestECDSAPeerKey_CollisionGuard(t *testing.T) {
	local := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("local-iss"))

	_, _, peerPub := issueECPeerToken(t)
	if err := local.AdoptVerifyKey(local.KeyID(), peerPub); err == nil {
		t.Fatal("expected collision error adopting under the active kid")
	}
	if err := local.AdoptVerifyKey("", peerPub); err == nil {
		t.Fatal("expected error on empty kid")
	}
	if err := local.AdoptVerifyKey("k", nil); err == nil {
		t.Fatal("expected error on nil key")
	}

	// A P-384 key is not P-256: ES256 rejects it.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("p384 keygen: %v", err)
	}
	if err := local.AdoptVerifyKey("p384", &p384.PublicKey); err == nil {
		t.Fatal("expected error adopting a non-P-256 key into an ES256 issuer")
	}
}
