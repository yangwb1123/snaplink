package ssoext

import (
	"context"
	"crypto"
	"testing"
)

// registerExternalSignerForTest registers a signer factory and unregisters
// it when the test ends, keeping the package-global registry clean across
// subtests and -count>1 runs. RegisterExternalSigner panics on a duplicate
// name by design (a production wiring guard), so tests must clean up rather
// than relax it — mirrors registerLDAPAuthenticatorsForTest.
func registerExternalSignerForTest(t *testing.T, name string, f ExternalSignerFactory) {
	t.Helper()
	RegisterExternalSigner(name, f)
	t.Cleanup(func() {
		ExternalSignerRegistry.Unregister(name)
	})
}

func TestRegisterExternalSigner_RegisterLookupList(t *testing.T) {
	t.Parallel()
	factory := func(context.Context) (crypto.Signer, string, error) {
		return nil, "kid", nil
	}
	registerExternalSignerForTest(t, "kms-ext-a", factory)
	registerExternalSignerForTest(t, "kms-ext-b", factory)

	if _, ok := LookupExternalSigner("kms-ext-a"); !ok {
		t.Error("LookupExternalSigner(kms-ext-a) = not found, want found")
	}
	if _, ok := LookupExternalSigner("kms-missing"); ok {
		t.Error("LookupExternalSigner(kms-missing) = found, want not found")
	}

	names := RegisteredExternalSigners()
	// Sorted output; both registered names present.
	if len(names) < 2 || names[0] != "kms-ext-a" || names[1] != "kms-ext-b" {
		t.Errorf("RegisteredExternalSigners() = %v, want [kms-ext-a kms-ext-b ...] sorted", names)
	}
}

func TestRegisterExternalSigner_RejectsBadInput(t *testing.T) {
	t.Parallel()
	good := func(context.Context) (crypto.Signer, string, error) {
		return nil, "kid", nil
	}
	// ssoextAssertPanic is defined in saml_registry_test.go (same package).
	ssoextAssertPanic(t, "empty name", func() { RegisterExternalSigner("", good) })
	ssoextAssertPanic(t, "nil factory", func() { RegisterExternalSigner("kms-ext-nilfac", nil) })

	registerExternalSignerForTest(t, "kms-ext-dup", good)
	ssoextAssertPanic(t, "duplicate", func() { RegisterExternalSigner("kms-ext-dup", good) })
}
