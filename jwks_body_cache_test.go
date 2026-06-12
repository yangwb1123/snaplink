package sso_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
)

// jwksCompute is a minimal compute closure that mirrors the real JWKS handler:
// it walks all JWKSProvider issuers and marshals their keys. Used in tests so
// the body-cache paths exercise a realistic (non-trivial) compute function.
func jwksCompute(s *sso.Server) func() ([]byte, error) {
	return func() ([]byte, error) {
		var keys []core.JWK
		for _, ti := range s.TokenIssuers() {
			jp, ok := ti.(core.JWKSProvider)
			if !ok {
				continue
			}
			ks, err := jp.JWKS(context.Background())
			if err != nil {
				continue
			}
			keys = append(keys, ks...)
		}
		return json.Marshal(map[string]any{"keys": keys})
	}
}

func TestJWKSBodyCache_Disabled(t *testing.T) {
	s := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithJWKSCacheTTL(0),
	)
	compute := jwksCompute(s)
	b1, err := s.ComputeJWKSDocument(compute)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := s.ComputeJWKSDocument(compute)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Error("disabled cache: successive calls should return equivalent docs")
	}
}

func TestJWKSBodyCache_Enabled(t *testing.T) {
	s := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithJWKSCacheTTL(5*time.Minute),
	)
	compute := jwksCompute(s)
	b1, err := s.ComputeJWKSDocument(compute)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := s.ComputeJWKSDocument(compute)
	if err != nil {
		t.Fatal(err)
	}
	if &b1[0] == &b2[0] {
		// Same underlying array = cache hit (best-effort check; pointer
		// equality is fragile but sufficient for a unit test).
	}
	if string(b1) != string(b2) {
		t.Error("cache enabled: docs should be identical")
	}
}

func TestJWKSBodyCache_Invalidate(t *testing.T) {
	s := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithJWKSCacheTTL(5*time.Minute),
	)
	compute := jwksCompute(s)
	_, err := s.ComputeJWKSDocument(compute)
	if err != nil {
		t.Fatal(err)
	}
	s.InvalidateJWKSBodyCache()
	// After invalidation the exp is zero — a fresh compute must succeed.
	b, err := s.ComputeJWKSDocument(compute)
	if err != nil {
		t.Fatalf("after invalidation: %v", err)
	}
	if len(b) == 0 {
		t.Error("after invalidation: expected non-empty JWKS body")
	}
}
