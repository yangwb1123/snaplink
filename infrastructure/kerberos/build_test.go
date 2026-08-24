package kerberosauth_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	kerberosauth "github.com/yangwb1123/snaplink/kerberos"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oidc"
)

// buildFakeValidator is a KDC-free SPNEGOValidator stand-in (same shape as
// the internal fakeValidator in kerberos_test.go, re-declared here because
// this test lives in the external package and the seam only needs the
// interface).
type buildFakeValidator struct{ principal, realm string }

func (f *buildFakeValidator) Validate(_ context.Context, _ []byte) (string, string, []string, error) {
	return f.principal, f.realm, nil, nil
}

// TestBuild_EmbeddedHostDeps proves the factory adaptation: the ROOT-module
// deps arrive as the standard host-API bundle (ssoext.KerberosServerDeps),
// and kerberosauth.Deps embeds it so a fork constructs Build's Deps with ONE
// field — `kerberosauth.Deps{KerberosServerDeps: d}` — exactly mirroring
// saml.Deps. Every promoted field name keeps working.
func TestBuild_EmbeddedHostDeps(t *testing.T) {
	t.Parallel()
	clients := defaultimpl.NewMemoryClientStore()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	issuer := defaultimpl.NewEd25519JWTIssuer()
	recorder := audit.New(audit.NewMemorySink(64))

	if err := clients.Add(context.Background(), &sso.Client{
		ID:            "kiosk-app",
		Active:        true,
		AllowedScopes: []string{sso.ScopeOpenID, "profile"},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	cfg := kerberosauth.Config{
		Name:             "kerberos",
		KeytabBytes:      []byte("not-a-real-keytab-the-fake-validator-bypasses-it"),
		ServicePrincipal: "HTTP/sso.example.com",
		Realm:            "EXAMPLE.COM",
		ClientID:         "kiosk-app",
	}
	res, err := kerberosauth.Build(kerberosauth.Deps{
		KerberosServerDeps: ssoext.KerberosServerDeps{
			ClientStore:            clients,
			SessionManager:         sessions,
			UserProvider:           users,
			IssuerForClient:        func(c *sso.Client) (string, sso.TokenIssuer, error) { return "jwt", issuer, nil },
			IDTokenIssuerForClient: func(c *sso.Client) (oidc.IDTokenIssuer, bool, error) { return issuer, true, nil },
			AuditRecorder:          recorder,
		},
	}, cfg, &buildFakeValidator{principal: "alice", realm: "EXAMPLE.COM"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Handlers) == 0 {
		t.Fatal("Build returned no handlers")
	}
	found := false
	for _, hs := range res.Handlers {
		if hs.Method == http.MethodGet {
			found = true
		}
	}
	if !found {
		t.Error("Build returned no GET leg; the Negotiate handshake needs one")
	}
}

// TestBuild_EmbeddedDepsStillFailClosed proves embedding did not weaken the
// required-dep checks: a missing ClientStore through the embedded host-API
// bundle still fails boot closed, exactly as before the migration.
func TestBuild_EmbeddedDepsStillFailClosed(t *testing.T) {
	t.Parallel()
	_, err := kerberosauth.Build(kerberosauth.Deps{
		KerberosServerDeps: ssoext.KerberosServerDeps{},
	}, kerberosauth.Config{
		Name:             "kerberos",
		KeytabBytes:      []byte("k"),
		ServicePrincipal: "HTTP/sso.example.com",
		Realm:            "EXAMPLE.COM",
		ClientID:         "kiosk-app",
	}, &buildFakeValidator{principal: "alice", realm: "EXAMPLE.COM"})
	if err == nil {
		t.Fatal("Build succeeded without a ClientStore; want a required-dep error")
	}
}
