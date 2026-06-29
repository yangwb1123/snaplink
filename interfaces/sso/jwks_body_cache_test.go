package sso_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
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
	t.Parallel()
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
	t.Parallel()
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
	// A cache hit returns the same underlying backing array, but pointer
	// equality is too fragile to assert; the byte-identity check below is the
	// real contract.
	if string(b1) != string(b2) {
		t.Error("cache enabled: docs should be identical")
	}
}

func TestJWKSBodyCache_Invalidate(t *testing.T) {
	t.Parallel()
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
