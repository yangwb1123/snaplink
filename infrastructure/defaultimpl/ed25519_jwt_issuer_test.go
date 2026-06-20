package defaultimpl_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

func TestEd25519JWT_RoundTrip(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("test-iss"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	tok, err := iss.Issue(context.Background(), &sso.Subject{
		ID:     "user-1",
		Claims: map[string]string{"email": "u@example.com"},
	}, []string{"read", "write"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// 3 segments → real JWT shape gateway parsers expect.
	if got := strings.Count(tok.AccessToken, "."); got != 2 {
		t.Fatalf("expected 3 segments in JWT, got %d", got+1)
	}

	claims, err := iss.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Issuer != "test-iss" {
		t.Errorf("Issuer = %q", claims.Issuer)
	}
	if claims.Extra["email"] != "u@example.com" {
		t.Errorf("Extra lost: %v", claims.Extra)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "read" {
		t.Errorf("Scopes mismatch: %v", claims.Scopes)
	}
}

func TestEd25519JWT_TamperedSignatureRejected(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)

	parts := strings.Split(tok.AccessToken, ".")
	// Flip last byte of signature.
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[len(sig)-1] ^= 0xFF
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	if _, err := iss.Validate(context.Background(), tampered); err == nil {
		t.Fatal("expected validation error for tampered signature")
	}
}

func TestEd25519JWT_TamperedPayloadRejected(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)

	parts := strings.Split(tok.AccessToken, ".")
	// Replace payload but keep signature → must fail.
	bad := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`)) + "." + parts[2]
	if _, err := iss.Validate(context.Background(), bad); err == nil {
		t.Fatal("expected error for tampered payload")
	}
}

func TestEd25519JWT_MalformedTokenRejected(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	cases := []string{"", "abc", "a.b", "a.b.c.d"}
	for _, s := range cases {
		if _, err := iss.Validate(context.Background(), s); err == nil {
			t.Errorf("Validate(%q) should fail", s)
		}
	}
}

func TestEd25519JWT_ExpiredTokenRejected(t *testing.T) {
	// 1ns TTL guarantees expiry by the time Validate runs.
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Nanosecond))
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)
	time.Sleep(2 * time.Millisecond)
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("expected expired-token error")
	}
}

func TestEd25519JWT_RevokeBlocksValidate(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)

	if err := iss.Revoke(context.Background(), tok.AccessToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("revoked token should fail validation")
	}
}

func TestEd25519JWT_RevokeUnknownReturnsError(t *testing.T) {
	// Tokens not signed by this issuer cannot be revoked — keeps
	// revokeAcrossIssuers attribution correct.
	iss := defaultimpl.NewEd25519JWTIssuer()
	other := defaultimpl.NewEd25519JWTIssuer()
	tok, _ := other.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)

	if err := iss.Revoke(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("expected error revoking foreign token")
	}
}

func TestEd25519JWT_JWKSExposesPublicKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(priv),
		defaultimpl.WithEd25519KeyID("kid-1"),
	)

	keys, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	k := keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" {
		t.Errorf("unexpected JWK: %+v", k)
	}
	if k.Kid != "kid-1" {
		t.Errorf("Kid = %q", k.Kid)
	}
	rawPub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatalf("X decode: %v", err)
	}
	if !ed25519.PublicKey(rawPub).Equal(pub) {
		t.Errorf("JWK X does not match supplied public key")
	}
}

func TestEd25519JWT_KidIsDeterministic(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Key(priv))
	b := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Key(priv))
	if a.KeyID() != b.KeyID() {
		t.Fatalf("same key should yield same kid; got %q vs %q", a.KeyID(), b.KeyID())
	}
}
