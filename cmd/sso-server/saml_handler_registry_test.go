package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoext"
)

// registerSAMLHandlersForTest registers a SAML factory and unregisters it
// when the test ends, keeping the package-global registry clean across
// subtests and -count>1 runs. RegisterSAMLHandlers panics on a duplicate
// name by design (a production wiring guard), so tests must clean up rather
// than relax it — mirrors registerExternalSignerForTest.
func registerSAMLHandlersForTest(t *testing.T, name string, f ssoext.SAMLHandlerFactory) {
	t.Helper()
	ssoext.RegisterSAMLHandlers(name, f)
	t.Cleanup(func() {
		ssoext.SAMLHandlerRegistry.Unregister(name)
	})
}

// fakeSAMLAuthenticator is a stand-in SP-side SAML authenticator a factory
// hands back for cmd to register. It implements sso.Authenticator minimally
// (the registry seam only needs Name() to land it in the authenticators
// map).
type fakeSAMLAuthenticator struct{ name string }

func (a fakeSAMLAuthenticator) Name() string { return a.name }
func (a fakeSAMLAuthenticator) Authenticate(context.Context, *sso.AuthRequest) (*sso.AuthResult, error) {
	return nil, nil
}
func (a fakeSAMLAuthenticator) Callback(context.Context, *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, nil
}
func (a fakeSAMLAuthenticator) LoginURL(string) string { return "" }

// TestSAMLUnconfigured_NoRoutesMounted proves the nil-default byte-identical
// contract: with cfg.SAML.Handler == "" (the zero value), buildApp mounts NO
// SAML route — /saml/metadata 404s exactly as on a build without the feature.
// No factory is registered, so the lookup block never runs.
func TestSAMLUnconfigured_NoRoutesMounted(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{} // SAML.Handler == "" (disabled)
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	// Run the full handler-composition path (where the SAML block lives) to
	// prove the empty handler mounts nothing.
	if _, err := buildHTTPHandler(cfg, a, quietLogger()); err != nil {
		t.Fatalf("buildHTTPHandler: %v", err)
	}

	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + sso.PathSAMLMetadata)
	if err != nil {
		t.Fatalf("GET %s: %v", sso.PathSAMLMetadata, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET %s = %d, want 404 (no SAML route when saml.handler is empty)", sso.PathSAMLMetadata, resp.StatusCode)
	}
}

// TestSAMLConfigured_MountsRoutesAndAuthenticator proves the wiring path: a
// registered factory is looked up, its handlers mount on the SSO router, its
// authenticator registers, and its deps carry the server seams (issuer +
// IssuerForClient + stores). Asserting the route serves and the auth is in
// the map is the positive counterpart to the byte-identical test.
func TestSAMLConfigured_MountsRoutesAndAuthenticator(t *testing.T) {
	t.Parallel()
	var gotDeps ssoext.SAMLServerDeps
	factory := func(_ context.Context, deps ssoext.SAMLServerDeps) (*ssoext.SAMLHandlerSet, error) {
		gotDeps = deps
		return &ssoext.SAMLHandlerSet{
			Handlers: []ssoext.SAMLHandler{{
				Method: http.MethodGet,
				Path:   sso.PathSAMLMetadata,
				Handler: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("saml-metadata"))
				},
			}},
			Authenticators: []sso.Authenticator{fakeSAMLAuthenticator{name: "saml"}},
		}, nil
	}
	registerSAMLHandlersForTest(t, "test-saml", factory)

	cfg := &config.Config{}
	cfg.SAML.Handler = "test-saml"
	cfg.Server.Issuer = "https://sso.test"

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	// buildHTTPHandler is where the SAML block runs (run() calls it after
	// buildApp); invoke it directly so the test exercises the mount path.
	if _, err := buildHTTPHandler(cfg, a, quietLogger()); err != nil {
		t.Fatalf("buildHTTPHandler: %v", err)
	}

	// The factory received the server seams.
	if gotDeps.IssuerForClient == nil {
		t.Error("SAMLServerDeps.IssuerForClient not wired")
	}
	if gotDeps.RegisterAuthenticator == nil {
		t.Error("SAMLServerDeps.RegisterAuthenticator not wired")
	}
	if gotDeps.ClientStore == nil || gotDeps.SessionManager == nil || gotDeps.UserProvider == nil {
		t.Error("SAMLServerDeps stores not wired")
	}
	if gotDeps.Issuer != "https://sso.test" {
		t.Errorf("SAMLServerDeps.Issuer = %q, want https://sso.test", gotDeps.Issuer)
	}

	// The handler mounted and serves.
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + sso.PathSAMLMetadata)
	if err != nil {
		t.Fatalf("GET %s: %v", sso.PathSAMLMetadata, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s = %d, want 200 (SAML route mounted)", sso.PathSAMLMetadata, resp.StatusCode)
	}
}

// TestSAMLConfigured_UnregisteredHandlerFailsBoot proves a saml.handler that
// names no registered factory fails boot (rather than silently skipping SAML)
// — a misconfiguration, surfaced loudly with the list of registered names.
func TestSAMLConfigured_UnregisteredHandlerFailsBoot(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SAML.Handler = "does-not-exist"

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	// The unregistered-handler error surfaces from buildHTTPHandler (the
	// lookup site), which run() treats as fatal.
	if _, err := buildHTTPHandler(cfg, a, quietLogger()); err == nil {
		t.Fatal("buildHTTPHandler succeeded with an unregistered saml.handler; want a boot error")
	}
}
