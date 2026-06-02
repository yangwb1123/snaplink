package defaultimpl_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// issueRSAPeerToken mints a token from a separate "peer" RSA issuer of the
// given alg (RS256 or PS256) and returns the token plus the peer's kid + public
// key (the material a real replica would publish to the shared registry).
func issueRSAPeerToken(t *testing.T, alg string) (token, peerKid string, peerPub *rsa.PublicKey) {
	t.Helper()
	peer := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("peer-iss"),
		defaultimpl.WithRSAAlg(alg),
		defaultimpl.WithRSATokenTTL(5*time.Minute),
	)
	tok, err := peer.Issue(context.Background(), &sso.Subject{ID: "user-peer"}, []string{"read"})
	if err != nil {
		t.Fatalf("peer Issue: %v", err)
	}
	return tok.AccessToken, peer.KeyID(), peer.PublicKey()
}

// TestRSAPeerKey_AdoptAppearsInJWKS proves an adopted RSA peer key surfaces in
// JWKS as a verify-only (use:sig) RSA entry stamped with the LOCAL issuer's alg.
func TestRSAPeerKey_AdoptAppearsInJWKS(t *testing.T) {
	local := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("local-iss"),
		defaultimpl.WithRSAAlg("RS256"),
	)
	_, peerKid, peerPub := issueRSAPeerToken(t, "RS256")

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
	if found.Alg != "RS256" || found.Kty != "RSA" {
		t.Errorf("peer JWK shape wrong: %+v", found)
	}
	if found.N == "" || found.E == "" {
		t.Errorf("peer RSA JWK missing n/e: %+v", found)
	}
}

// TestRSAPeerKey_AdoptedTokenValidates proves a token signed by a SEPARATE
// RS256 issuer validates on the local RS256 issuer after adoption.
func TestRSAPeerKey_AdoptedTokenValidates(t *testing.T) {
	local := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("local-iss"),
		defaultimpl.WithRSAAlg("RS256"),
	)
	token, peerKid, peerPub := issueRSAPeerToken(t, "RS256")

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

// TestRSAPeerKey_PS256AdoptedTokenValidates proves the same property for the
// PSS padding: a PS256 peer token validates on a PS256 local issuer after
// adoption (RS256 and PS256 each carry their own routed verify path).
func TestRSAPeerKey_PS256AdoptedTokenValidates(t *testing.T) {
	local := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("local-iss"),
		defaultimpl.WithRSAAlg("PS256"),
	)
	token, peerKid, peerPub := issueRSAPeerToken(t, "PS256")

	if err := local.AdoptVerifyKey(peerKid, peerPub); err != nil {
		t.Fatalf("AdoptVerifyKey: %v", err)
	}
	if _, err := local.Validate(context.Background(), token); err != nil {
		t.Fatalf("Validate PS256 after adoption: %v", err)
	}
}

// TestRSAPeerKey_LocalRotationLeavesPeerKeys proves the local key lifecycle
// never touches adopted peer keys.
func TestRSAPeerKey_LocalRotationLeavesPeerKeys(t *testing.T) {
	local := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("local-iss"),
		defaultimpl.WithRSAAlg("RS256"),
	)
	token, peerKid, peerPub := issueRSAPeerToken(t, "RS256")
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

	local.DropVerifyKey(peerKid)
	jwks, _ = local.JWKS(context.Background())
	if jwksHasKid(jwks, peerKid) {
		t.Fatalf("peer kid %q still present after DropVerifyKey", peerKid)
	}
}

// TestRSAPeerKey_AlgConfusionRejected proves an RS256 peer token is rejected by
// an ES256 issuer (the alg gate runs before key lookup).
func TestRSAPeerKey_AlgConfusionRejected(t *testing.T) {
	token, _, _ := issueRSAPeerToken(t, "RS256")

	ecIss := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("ec-iss"))
	if _, err := ecIss.Validate(context.Background(), token); err == nil {
		t.Fatal("ES256 issuer accepted an RS256 token — alg gate breached")
	}
}

// TestRSAPeerKey_RS256VsPS256Strict locks the RS256/PS256 boundary at the
// ISSUER's alg gate: an RS256 issuer rejects a PS256 token even when it has
// adopted the PS256 peer's verify key (and symmetrically). The key material is
// identical across paddings; only the alg gate distinguishes them, so a PS256
// token must never verify on an RS256 issuer.
func TestRSAPeerKey_RS256VsPS256Strict(t *testing.T) {
	// RS256 issuer, PS256 peer token + key.
	rsLocal := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("rs-local"),
		defaultimpl.WithRSAAlg("RS256"),
	)
	psToken, psKid, psPub := issueRSAPeerToken(t, "PS256")
	// Even if the operator force-adopts the PS256 key into the RS256 issuer,
	// the alg gate (h.Alg must equal the issuer's RS256) rejects the PS256
	// token before any key lookup.
	if err := rsLocal.AdoptVerifyKey(psKid, psPub); err != nil {
		t.Fatalf("AdoptVerifyKey (rs adopting ps key material): %v", err)
	}
	if _, err := rsLocal.Validate(context.Background(), psToken); err == nil {
		t.Fatal("RS256 issuer accepted a PS256 token — RS256/PS256 gate breached")
	}

	// PS256 issuer, RS256 peer token + key: symmetric rejection.
	psLocal := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("ps-local"),
		defaultimpl.WithRSAAlg("PS256"),
	)
	rsToken, rsKid, rsPub := issueRSAPeerToken(t, "RS256")
	if err := psLocal.AdoptVerifyKey(rsKid, rsPub); err != nil {
		t.Fatalf("AdoptVerifyKey (ps adopting rs key material): %v", err)
	}
	if _, err := psLocal.Validate(context.Background(), rsToken); err == nil {
		t.Fatal("PS256 issuer accepted an RS256 token — RS256/PS256 gate breached")
	}
}

// TestRSAPeerKey_CollisionGuard proves adoption refuses a kid that collides
// with the local active signing key, an empty kid, a nil key, and an
// undersized (< 2048-bit) modulus.
func TestRSAPeerKey_CollisionGuard(t *testing.T) {
	local := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("local-iss"),
		defaultimpl.WithRSAAlg("RS256"),
	)

	_, _, peerPub := issueRSAPeerToken(t, "RS256")
	if err := local.AdoptVerifyKey(local.KeyID(), peerPub); err == nil {
		t.Fatal("expected collision error adopting under the active kid")
	}
	if err := local.AdoptVerifyKey("", peerPub); err == nil {
		t.Fatal("expected error on empty kid")
	}
	if err := local.AdoptVerifyKey("k", nil); err == nil {
		t.Fatal("expected error on nil key")
	}

	// A 1024-bit key is below the 2048-bit floor: adoption must reject it.
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("weak keygen: %v", err)
	}
	if err := local.AdoptVerifyKey("weak", &weak.PublicKey); err == nil {
		t.Fatal("expected error adopting a sub-2048-bit key")
	}
}
