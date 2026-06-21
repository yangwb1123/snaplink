package defaultimpl_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// jwtSigner is the subset of issuer behavior the cross-issuer extras tests
// exercise uniformly across Ed25519 / ECDSA / RSA.
type jwtSigner interface {
	SignMetadata(ctx context.Context, claims map[string]any) (string, error)
	SignUserInfo(ctx context.Context, audience string, claims map[string]any) (string, error)
	IssueLogoutToken(ctx context.Context, req *sso.LogoutTokenRequest) (string, error)
	SignJWT(ctx context.Context, typ string, claims any) (string, error)
	AcceptsTokenFormat(token string) bool
}

func issuerSigners(t *testing.T) map[string]jwtSigner {
	t.Helper()
	return map[string]jwtSigner{
		"ed25519": defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("iss")),
		"ecdsa":   defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("iss")),
		"rsa":     defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAIssuer("iss")),
	}
}

func threeSegments(s string) bool { return strings.Count(s, ".") == 2 }

func TestIssuers_SignMetadata(t *testing.T) {
	ctx := context.Background()
	for name, iss := range issuerSigners(t) {
		t.Run(name, func(t *testing.T) {
			jws, err := iss.SignMetadata(ctx, map[string]any{"issuer": "iss", "x": 1})
			if err != nil {
				t.Fatalf("SignMetadata: %v", err)
			}
			if !threeSegments(jws) {
				t.Fatalf("metadata JWS not 3-segment: %q", jws)
			}
			// nil claims → empty string, no error (defensive shape).
			empty, err := iss.SignMetadata(ctx, nil)
			if err != nil {
				t.Fatalf("SignMetadata(nil): %v", err)
			}
			if empty != "" {
				t.Errorf("SignMetadata(nil) = %q, want empty", empty)
			}
		})
	}
}

func TestIssuers_SignUserInfo(t *testing.T) {
	ctx := context.Background()
	for name, iss := range issuerSigners(t) {
		t.Run(name, func(t *testing.T) {
			// nil claims → issuer stamps iss + aud defaults.
			jws, err := iss.SignUserInfo(ctx, "client-1", nil)
			if err != nil {
				t.Fatalf("SignUserInfo(nil): %v", err)
			}
			if !threeSegments(jws) {
				t.Fatalf("userinfo JWS not 3-segment: %q", jws)
			}
			var claims map[string]any
			pb, _ := base64.RawURLEncoding.DecodeString(strings.Split(jws, ".")[1])
			_ = json.Unmarshal(pb, &claims)
			if claims["iss"] != "iss" {
				t.Errorf("iss = %v, want iss", claims["iss"])
			}
			if claims["aud"] != "client-1" {
				t.Errorf("aud = %v, want client-1", claims["aud"])
			}

			// Caller-supplied iss/aud are NOT overridden.
			jws2, err := iss.SignUserInfo(ctx, "client-1", map[string]any{"iss": "custom", "aud": "other", "name": "Jo"})
			if err != nil {
				t.Fatalf("SignUserInfo: %v", err)
			}
			pb2, _ := base64.RawURLEncoding.DecodeString(strings.Split(jws2, ".")[1])
			var c2 map[string]any
			_ = json.Unmarshal(pb2, &c2)
			if c2["iss"] != "custom" || c2["aud"] != "other" {
				t.Errorf("caller iss/aud overridden: %v", c2)
			}

			// Empty audience omits the default aud injection.
			jws3, _ := iss.SignUserInfo(ctx, "", map[string]any{"sub": "u"})
			pb3, _ := base64.RawURLEncoding.DecodeString(strings.Split(jws3, ".")[1])
			var c3 map[string]any
			_ = json.Unmarshal(pb3, &c3)
			if _, ok := c3["aud"]; ok {
				t.Errorf("empty audience must not inject aud: %v", c3)
			}
		})
	}
}

func TestIssuers_IssueLogoutToken(t *testing.T) {
	ctx := context.Background()
	for name, iss := range issuerSigners(t) {
		t.Run(name, func(t *testing.T) {
			tok, err := iss.IssueLogoutToken(ctx, &sso.LogoutTokenRequest{
				Subject:  "sub",
				Audience: "client",
				SID:      "sess-1",
			})
			if err != nil {
				t.Fatalf("IssueLogoutToken: %v", err)
			}
			if !threeSegments(tok) {
				t.Fatalf("logout token not 3-segment: %q", tok)
			}
			// OIDC BCL §2.4: typ=logout+jwt, events claim present, sid carried.
			hb, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
			var hdr struct{ Typ string }
			_ = json.Unmarshal(hb, &hdr)
			if hdr.Typ != "logout+jwt" {
				t.Errorf("typ = %q, want logout+jwt", hdr.Typ)
			}
			pb, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
			var pl map[string]any
			_ = json.Unmarshal(pb, &pl)
			if _, ok := pl["events"]; !ok {
				t.Error("logout token missing events claim")
			}
			if pl["sid"] != "sess-1" {
				t.Errorf("sid = %v, want sess-1", pl["sid"])
			}

			// Missing subject/audience is an error (no nil panic).
			if _, err := iss.IssueLogoutToken(ctx, &sso.LogoutTokenRequest{Subject: "s"}); err == nil {
				t.Error("logout token without audience must error")
			}
			if _, err := iss.IssueLogoutToken(ctx, nil); err == nil {
				t.Error("logout token with nil request must error")
			}
		})
	}
}

func TestIssuers_SignJWT(t *testing.T) {
	ctx := context.Background()
	for name, iss := range issuerSigners(t) {
		t.Run(name, func(t *testing.T) {
			tok, err := iss.SignJWT(ctx, "secevent+jwt", map[string]any{"jti": "1", "iss": "iss"})
			if err != nil {
				t.Fatalf("SignJWT: %v", err)
			}
			if !threeSegments(tok) {
				t.Fatalf("SignJWT not 3-segment: %q", tok)
			}
			hb, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
			var hdr struct{ Typ string }
			_ = json.Unmarshal(hb, &hdr)
			if hdr.Typ != "secevent+jwt" {
				t.Errorf("typ = %q, want secevent+jwt", hdr.Typ)
			}
			// Empty typ is rejected (a SET must be distinguishable on the wire).
			if _, err := iss.SignJWT(ctx, "", map[string]any{}); err == nil {
				t.Error("SignJWT with empty typ must error")
			}
		})
	}
}

func TestIssuers_AcceptsTokenFormat(t *testing.T) {
	for name, iss := range issuerSigners(t) {
		t.Run(name, func(t *testing.T) {
			if !iss.AcceptsTokenFormat("a.b.c") {
				t.Error("3-segment token should be accepted")
			}
			if iss.AcceptsTokenFormat("") {
				t.Error("empty token must be rejected")
			}
			if iss.AcceptsTokenFormat("a.b") {
				t.Error("2-segment token must be rejected")
			}
			if iss.AcceptsTokenFormat("a.b.c.d") {
				t.Error("4-segment token must be rejected")
			}
		})
	}
}

// TestECDSAIssuer_Options exercises WithECDSAKey / WithECDSAKeyID /
// WithECDSAVerifyKey, none of which were covered.
func TestECDSAIssuer_Options(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAKey(priv),
		defaultimpl.WithECDSAKeyID("kid-ec"),
		defaultimpl.WithECDSAVerifyKey("old-kid", &other.PublicKey),
	)
	if iss.KeyID() != "kid-ec" {
		t.Errorf("KeyID = %q, want kid-ec", iss.KeyID())
	}
	if !iss.PublicKey().Equal(&priv.PublicKey) {
		t.Error("PublicKey does not match supplied key")
	}
	// JWKS publishes both the primary and the extra verify key.
	jwks, _ := iss.JWKS(context.Background())
	if len(jwks) != 2 {
		t.Errorf("JWKS keys = %d, want 2 (primary + verify)", len(jwks))
	}
}

// TestRSAIssuer_Options exercises WithRSAKeyID / WithRSAVerifyKey.
func TestRSAIssuer_Options(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	iss := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAKey(priv),
		defaultimpl.WithRSAKeyID("kid-rsa"),
		defaultimpl.WithRSAVerifyKey("old-kid", &other.PublicKey),
	)
	if iss.KeyID() != "kid-rsa" {
		t.Errorf("KeyID = %q, want kid-rsa", iss.KeyID())
	}
	jwks, _ := iss.JWKS(context.Background())
	if len(jwks) != 2 {
		t.Errorf("JWKS keys = %d, want 2", len(jwks))
	}
}

// softwareRSAExtSigner mirrors the production softwareRSASigner (RS256) for
// the external-signer seam.
type softwareRSAExtSigner struct{ priv *rsa.PrivateKey }

func (s softwareRSAExtSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	d := sha256.Sum256(message)
	return rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, d[:])
}

func TestRSAIssuer_ExternalSigner(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	iss := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAExternalSigner(softwareRSAExtSigner{priv}, &priv.PublicKey, "ext-rsa"),
	)
	if iss.KeyID() != "ext-rsa" {
		t.Errorf("KeyID = %q, want ext-rsa", iss.KeyID())
	}
	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestECDSAIssuer_RevocationSurvivesRestart mirrors the Ed25519 restart-survival
// contract for the ECDSA issuer (exercises SeedRevocations + WithECDSARevocationStore).
func TestECDSAIssuer_RevocationSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	store := defaultimpl.NewMemoryRevocationStore()
	mk := func() *defaultimpl.ECDSAJWTIssuer {
		return defaultimpl.NewECDSAJWTIssuer(
			defaultimpl.WithECDSAIssuer("iss"),
			defaultimpl.WithECDSAKey(priv),
			defaultimpl.WithECDSAKeyID("k1"),
			defaultimpl.WithECDSARevocationStore(store),
		)
	}
	a := mk()
	tok, _ := a.Issue(ctx, &sso.Subject{ID: "u", ClientID: "c"}, []string{"openid"})
	if err := a.Revoke(ctx, tok.AccessToken); err != nil {
		t.Fatal(err)
	}

	b := mk()
	if _, err := b.Validate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("pre-seed B should accept: %v", err)
	}
	if err := b.SeedRevocations(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Validate(ctx, tok.AccessToken); err == nil {
		t.Fatal("after SeedRevocations the revoked token must be rejected on B")
	}
	// nil-store SeedRevocations is a no-op.
	plain := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("iss"))
	if err := plain.SeedRevocations(ctx); err != nil {
		t.Errorf("SeedRevocations(nil store) = %v", err)
	}
}

func TestRSAIssuer_RevocationSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := defaultimpl.NewMemoryRevocationStore()
	mk := func() *defaultimpl.RSAJWTIssuer {
		return defaultimpl.NewRSAJWTIssuer(
			defaultimpl.WithRSAIssuer("iss"),
			defaultimpl.WithRSAKey(priv),
			defaultimpl.WithRSAKeyID("k1"),
			defaultimpl.WithRSARevocationStore(store),
		)
	}
	a := mk()
	tok, _ := a.Issue(ctx, &sso.Subject{ID: "u", ClientID: "c"}, []string{"openid"})
	if err := a.Revoke(ctx, tok.AccessToken); err != nil {
		t.Fatal(err)
	}

	b := mk()
	if _, err := b.Validate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("pre-seed B should accept: %v", err)
	}
	if err := b.SeedRevocations(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Validate(ctx, tok.AccessToken); err == nil {
		t.Fatal("after SeedRevocations the revoked token must be rejected on B")
	}
	plain := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAIssuer("iss"))
	if err := plain.SeedRevocations(ctx); err != nil {
		t.Errorf("SeedRevocations(nil store) = %v", err)
	}
}

// TestEd25519Issuer_VerifyKeyOption covers WithEd25519VerifyKey (a token from a
// rotated-out key still verifies when its public half is registered).
func TestEd25519Issuer_VerifyKeyOption(t *testing.T) {
	ctx := context.Background()
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldIss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("iss"), defaultimpl.WithEd25519Key(oldPriv))
	oldTok, _ := oldIss.Issue(ctx, &sso.Subject{ID: "u", ClientID: "c"}, nil)

	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("iss"),
		defaultimpl.WithEd25519Key(newPriv),
		defaultimpl.WithEd25519VerifyKey(oldIss.KeyID(), oldPub),
	)
	if _, err := iss.Validate(ctx, oldTok.AccessToken); err != nil {
		t.Fatalf("token from registered verify key rejected: %v", err)
	}
}
