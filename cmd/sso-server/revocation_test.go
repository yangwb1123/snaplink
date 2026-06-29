package main

import (
	"context"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/shared/spi"
)

func TestBuildRevocationStore(t *testing.T) {
	t.Parallel()
	if s, err := serverbuildsign.BuildRevocationStore(config.SigningConfig{}); err != nil || s != nil {
		t.Errorf("empty backend = (%v, %v), want (nil, nil)", s, err)
	}
	if s, err := serverbuildsign.BuildRevocationStore(config.SigningConfig{RevocationBackend: "memory"}); err != nil || s == nil {
		t.Errorf("memory backend = (%v, %v), want a non-nil store", s, err)
	}
	if s, err := serverbuildsign.BuildRevocationStore(config.SigningConfig{
		RevocationBackend: "sqlite", RevocationDSN: "file:" + t.TempDir() + "/r.db",
	}); err != nil || s == nil {
		t.Errorf("sqlite backend = (%v, %v), want a non-nil store", s, err)
	}
	if _, err := serverbuildsign.BuildRevocationStore(config.SigningConfig{RevocationBackend: "sqlite"}); err == nil {
		t.Error("sqlite without a DSN should error")
	}
	if _, err := serverbuildsign.BuildRevocationStore(config.SigningConfig{RevocationBackend: "bogus"}); err == nil {
		t.Error("an unknown backend should error")
	}
}

// TestBuildSigningIssuer_WithRevocation: every alg constructs + seeds cleanly
// when a durable revocation backend is wired (the cmd plumbing for the durable
// revocation feature), and the issuer exposes the SeedRevocations seam.
func TestBuildSigningIssuer_WithRevocation(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{"eddsa", "es256", "rs256", "ps256"} {
		iss, _, _, err := serverbuildsign.BuildSigningIssuer(
			config.SigningConfig{Alg: alg, RevocationBackend: "memory"},
			config.ServerConfig{Issuer: "https://sso.test"},
			nil,
			spi.NopLogger{},
		)
		if err != nil {
			t.Errorf("%s with revocation backend: %v", alg, err)
			continue
		}
		if iss == nil {
			t.Errorf("%s: nil issuer", alg)
			continue
		}
		if _, ok := iss.(interface {
			SeedRevocations(context.Context) error
		}); !ok {
			t.Errorf("%s: issuer lacks the SeedRevocations seam", alg)
		}
	}
}
