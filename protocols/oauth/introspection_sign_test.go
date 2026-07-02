package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

// fakeJWKSProvider is a real, minimal core.JWKSProvider stand-in (no mocks
// per AGENTS.md) so IntrospectionKeySet can be tested without pulling in a
// concrete defaultimpl issuer (defaultimpl imports oauth; that would cycle).
type fakeJWKSProvider struct {
	keys []core.JWK
	err  error
}

func (f fakeJWKSProvider) JWKS(context.Context) ([]core.JWK, error) { return f.keys, f.err }

func TestIntrospectionKeySet(t *testing.T) {
	t.Parallel()

	t.Run("rewrites use to introspection, preserves other fields", func(t *testing.T) {
		inner := fakeJWKSProvider{keys: []core.JWK{
			{Kty: "OKP", Crv: "Ed25519", Kid: "k1", X: "abc", Use: "sig", Alg: "EdDSA"},
		}}
		ks := NewIntrospectionKeySet(inner)
		got, err := ks.JWKS(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d keys, want 1", len(got))
		}
		if got[0].Use != JWKUseIntrospection {
			t.Errorf("use = %q, want %q", got[0].Use, JWKUseIntrospection)
		}
		if got[0].Kid != "k1" || got[0].Alg != "EdDSA" || got[0].X != "abc" {
			t.Errorf("non-use fields must pass through unchanged: %+v", got[0])
		}
		// The wrapper must not mutate the wrapped provider's own slice.
		if inner.keys[0].Use != "sig" {
			t.Errorf("wrapping mutated the inner provider's key: %+v", inner.keys[0])
		}
	})

	t.Run("propagates the inner provider's error", func(t *testing.T) {
		boom := errors.New("boom")
		ks := NewIntrospectionKeySet(fakeJWKSProvider{err: boom})
		if _, err := ks.JWKS(context.Background()); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want %v", err, boom)
		}
	})

	t.Run("nil provider wraps to nil", func(t *testing.T) {
		if got := NewIntrospectionKeySet(nil); got != nil {
			t.Errorf("NewIntrospectionKeySet(nil) = %v, want nil", got)
		}
	})
}

func TestWantsIntrospectionJWT(t *testing.T) {
	t.Parallel()
	cases := []struct {
		accept string
		want   bool
	}{
		{"", false},
		{"application/json", false},
		{core.ContentTypeTokenIntrospectionJWT, true},
		{"application/json, " + core.ContentTypeTokenIntrospectionJWT + ";q=0.9", true},
	}
	for _, c := range cases {
		if got := WantsIntrospectionJWT(c.accept); got != c.want {
			t.Errorf("WantsIntrospectionJWT(%q) = %v, want %v", c.accept, got, c.want)
		}
	}
}

func TestSignIntrospectionResponse(t *testing.T) {
	t.Parallel()
	signer := &fakeIntrospectionSigner{}
	body := map[string]any{core.KeyActive: true, core.KeySub: "user-1"}

	jwt, err := SignIntrospectionResponse(context.Background(), signer, "https://issuer.test", "rp", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jwt == "" {
		t.Fatal("expected a non-empty signed JWT")
	}
	if signer.lastClaims[core.KeyIss] != "https://issuer.test" {
		t.Errorf("iss = %v", signer.lastClaims[core.KeyIss])
	}
	if signer.lastClaims[core.KeyAud] != "rp" {
		t.Errorf("aud = %v", signer.lastClaims[core.KeyAud])
	}
	if _, ok := signer.lastClaims[core.KeyIat]; !ok {
		t.Error("iat must be set")
	}
	nested, ok := signer.lastClaims[core.KeyTokenIntrospection].(map[string]any)
	if !ok {
		t.Fatalf("no nested %s claim", core.KeyTokenIntrospection)
	}
	if nested[core.KeySub] != "user-1" {
		t.Errorf("nested sub = %v, want user-1 (full body preserved)", nested[core.KeySub])
	}
}
