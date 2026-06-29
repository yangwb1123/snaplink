package defaultimpl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// issuePeerToken mints a token from a separate "peer" issuer and returns the
// token plus the peer's kid + public key (the material a real replica would
// publish to the shared signing-key registry).
func issuePeerToken(t *testing.T) (token, peerKid string, peerPub ed25519.PublicKey) {
	t.Helper()
	peer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("peer-iss"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	tok, err := peer.Issue(context.Background(), &sso.Subject{ID: "user-peer"}, []string{"read"})
	if err != nil {
		t.Fatalf("peer Issue: %v", err)
	}
	return tok.AccessToken, peer.KeyID(), peer.PublicKey()
}

// TestEd25519PeerKey_AdoptAppearsInJWKS proves an adopted peer key surfaces
// in JWKS as a verify-only (use:sig) entry under the peer's kid.
func TestEd25519PeerKey_AdoptAppearsInJWKS(t *testing.T) {
	t.Parallel()
	local := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("local-iss"))
	_, peerKid, peerPub := issuePeerToken(t)

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
	if found.Alg != "EdDSA" || found.Kty != "OKP" || found.Crv != "Ed25519" {
		t.Errorf("peer JWK shape wrong: %+v", found)
	}
}

// TestEd25519PeerKey_AdoptedTokenValidates proves a token signed by a
// SEPARATE issuer validates on the local issuer after adoption — the core
// cross-replica verification property.
func TestEd25519PeerKey_AdoptedTokenValidates(t *testing.T) {
	t.Parallel()
	local := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("local-iss"))
	token, peerKid, peerPub := issuePeerToken(t)

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

// TestEd25519PeerKey_LocalRotationLeavesPeerKeys proves the local key
// lifecycle (RotateKey / RetireKey) never touches adopted peer keys — peer
// lifecycle is owned by the registry side, not local rotation.
func TestEd25519PeerKey_LocalRotationLeavesPeerKeys(t *testing.T) {
	t.Parallel()
	local := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("local-iss"))
	token, peerKid, peerPub := issuePeerToken(t)
	if err := local.AdoptVerifyKey(peerKid, peerPub); err != nil {
		t.Fatalf("AdoptVerifyKey: %v", err)
	}

	// Rotate the local signing key, then retire the demoted one.
	oldKID := local.KeyID()
	if _, err := local.RotateKey(nil); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if err := local.RetireKey(oldKID); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}

	// The peer key must survive local rotation+retirement: still in JWKS and
	// still able to verify the peer token.
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

	// And DropVerifyKey removes ONLY the peer key.
	local.DropVerifyKey(peerKid)
	jwks, _ = local.JWKS(context.Background())
	if jwksHasKid(jwks, peerKid) {
		t.Fatalf("peer kid %q still present after DropVerifyKey", peerKid)
	}
}

// TestEd25519PeerKey_AlgConfusionRejected proves an EdDSA peer token is
// rejected by an ECDSA issuer: the alg gate runs BEFORE key lookup, so an
// adopted-or-not EdDSA key can never be reached on the ES256 verify path.
func TestEd25519PeerKey_AlgConfusionRejected(t *testing.T) {
	t.Parallel()
	token, _, _ := issuePeerToken(t)

	ecIss := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("ec-iss"))
	if _, err := ecIss.Validate(context.Background(), token); err == nil {
		t.Fatal("ECDSA issuer accepted an EdDSA token — alg gate breached")
	}

	// Sanity: a fresh ECDSA key + value used by the test compiles/links.
	if _, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
}

// TestEd25519PeerKey_CollisionGuard proves adoption refuses a kid that
// collides with the local active signing key (defensive guard against two
// distinct keys claiming one kid).
func TestEd25519PeerKey_CollisionGuard(t *testing.T) {
	t.Parallel()
	local := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("local-iss"))

	_, _, peerPub := issuePeerToken(t)
	if err := local.AdoptVerifyKey(local.KeyID(), peerPub); err == nil {
		t.Fatal("expected collision error adopting under the active kid")
	}

	// Empty kid and bad key length are also rejected.
	if err := local.AdoptVerifyKey("", peerPub); err == nil {
		t.Fatal("expected error on empty kid")
	}
	if err := local.AdoptVerifyKey("k", ed25519.PublicKey{1, 2, 3}); err == nil {
		t.Fatal("expected error on wrong-length key")
	}
}

func jwksHasKid(jwks []sso.JWK, kid string) bool {
	for _, k := range jwks {
		if k.Kid == kid {
			return true
		}
	}
	return false
}
