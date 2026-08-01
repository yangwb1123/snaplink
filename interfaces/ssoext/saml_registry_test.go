package ssoext

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// registerSAMLHandlersForTest registers a SAML factory and unregisters it
// when the test ends, keeping the package-global registry clean across
// subtests and -count>1 runs. RegisterSAMLHandlers panics on a duplicate
// name by design (a production wiring guard), so tests must clean up rather
// than relax it — mirrors registerExternalSignerForTest.
func registerSAMLHandlersForTest(t *testing.T, name string, f SAMLHandlerFactory) {
	t.Helper()
	RegisterSAMLHandlers(name, f)
	t.Cleanup(func() {
		SAMLHandlerRegistry.Unregister(name)
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

func TestRegisterSAMLHandlers_RegisterLookupList(t *testing.T) {
	t.Parallel()
	factory := func(context.Context, SAMLServerDeps) (*SAMLHandlerSet, error) {
		return &SAMLHandlerSet{}, nil
	}
	registerSAMLHandlersForTest(t, "saml-a", factory)
	registerSAMLHandlersForTest(t, "saml-b", factory)

	if _, ok := LookupSAMLHandlerFactory("saml-a"); !ok {
		t.Error("LookupSAMLHandlerFactory(saml-a) = not found, want found")
	}
	if _, ok := LookupSAMLHandlerFactory("saml-missing"); ok {
		t.Error("LookupSAMLHandlerFactory(saml-missing) = found, want not found")
	}

	names := RegisteredSAMLHandlers()
	// Sorted output; both registered names present.
	if len(names) < 2 || names[0] != "saml-a" || names[1] != "saml-b" {
		t.Errorf("RegisteredSAMLHandlers() = %v, want [saml-a saml-b ...] sorted", names)
	}
}

func TestRegisterSAMLHandlers_RejectsBadInput(t *testing.T) {
	t.Parallel()
	good := func(context.Context, SAMLServerDeps) (*SAMLHandlerSet, error) { return &SAMLHandlerSet{}, nil }
	// assertPanic is defined in external_signer_test.go (same package).
	ssoextAssertPanic(t, "empty name", func() { RegisterSAMLHandlers("", good) })
	ssoextAssertPanic(t, "nil factory", func() { RegisterSAMLHandlers("saml-nilfac", nil) })

	registerSAMLHandlersForTest(t, "saml-dup", good)
	ssoextAssertPanic(t, "duplicate", func() { RegisterSAMLHandlers("saml-dup", good) })
}

// ssoextAssertPanic is the local panic assertion helper (mirrors the one in
// cmd/sso-server's external_signer_test.go).
func ssoextAssertPanic(t *testing.T, label string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: want panic", label)
		}
	}()
	f()
}
