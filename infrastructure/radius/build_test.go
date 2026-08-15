package radiusauth

import (
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// TestBuild_WiresHostDepsAndConfig proves the factory adaptation: Build
// plumbs the host-API Logger into the authenticator and returns it as an
// sso.Authenticator, so a fork's factory maps `radiusauth.Build(radiusauth.
// Deps{RADIUSServerDeps: d}, cfg)` straight onto
// ssoext.RADIUSAuthenticatorSet — the SAML-registry pattern (no field-for-
// field copy; the embedding keeps the field names).
func TestBuild_WiresHostDepsAndConfig(t *testing.T) {
	t.Parallel()
	fake := &fakeExchanger{accept: true}
	cfg := Config{
		Name:         "test-radius",
		Servers:      []string{"radius.example.com:1812"},
		SharedSecret: "test-secret",
	}
	res, err := Build(Deps{
		RADIUSServerDeps: ssoext.RADIUSServerDeps{Logger: spi.NopLogger{}},
	}, cfg, WithExchanger(fake))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Authenticators) != 1 {
		t.Fatalf("Build produced %d authenticators, want 1", len(res.Authenticators))
	}
	if got := res.Authenticators[0].Name(); got != "test-radius" {
		t.Errorf("authenticator Name = %q, want test-radius", got)
	}
}

// TestBuild_InvalidConfigFailsClosed proves a bad config fails the operator's
// boot CLOSED through Build, exactly as through New (a credential-auth gate
// with no shared secret must not start).
func TestBuild_InvalidConfigFailsClosed(t *testing.T) {
	t.Parallel()
	if _, err := Build(Deps{}, Config{Name: "broken", Servers: []string{"radius.example.com:1812"}}); err == nil {
		t.Fatal("Build succeeded without a SharedSecret; want a validation error")
	}
}
