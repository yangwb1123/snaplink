package ssoext

import (
	"context"
	"testing"
)

// registerLDAPAuthenticatorsForTest registers an LDAP factory and unregisters
// it when the test ends, keeping the package-global registry clean across
// subtests and -count>1 runs. RegisterLDAPAuthenticators panics on a
// duplicate name by design (a production wiring guard), so tests must clean
// up rather than relax it — mirrors registerSAMLHandlersForTest.
func registerLDAPAuthenticatorsForTest(t *testing.T, name string, f LDAPAuthenticatorFactory) {
	t.Helper()
	RegisterLDAPAuthenticators(name, f)
	t.Cleanup(func() {
		LDAPAuthenticatorRegistry.Unregister(name)
	})
}

func TestRegisterLDAPAuthenticators_RegisterLookupList(t *testing.T) {
	t.Parallel()
	factory := func(context.Context, LDAPServerDeps) (*LDAPAuthenticatorSet, error) {
		return &LDAPAuthenticatorSet{}, nil
	}
	registerLDAPAuthenticatorsForTest(t, "ldap-a", factory)
	registerLDAPAuthenticatorsForTest(t, "ldap-b", factory)

	if _, ok := LookupLDAPAuthenticatorFactory("ldap-a"); !ok {
		t.Error("LookupLDAPAuthenticatorFactory(ldap-a) = not found, want found")
	}
	if _, ok := LookupLDAPAuthenticatorFactory("ldap-missing"); ok {
		t.Error("LookupLDAPAuthenticatorFactory(ldap-missing) = found, want not found")
	}

	names := RegisteredLDAPAuthenticators()
	// Sorted output; both registered names present.
	if len(names) < 2 || names[0] != "ldap-a" || names[1] != "ldap-b" {
		t.Errorf("RegisteredLDAPAuthenticators() = %v, want [ldap-a ldap-b ...] sorted", names)
	}
}

func TestRegisterLDAPAuthenticators_RejectsBadInput(t *testing.T) {
	t.Parallel()
	good := func(context.Context, LDAPServerDeps) (*LDAPAuthenticatorSet, error) {
		return &LDAPAuthenticatorSet{}, nil
	}
	// ssoextAssertPanic is defined in saml_registry_test.go (same package).
	ssoextAssertPanic(t, "empty name", func() { RegisterLDAPAuthenticators("", good) })
	ssoextAssertPanic(t, "nil factory", func() { RegisterLDAPAuthenticators("ldap-nilfac", nil) })

	registerLDAPAuthenticatorsForTest(t, "ldap-dup", good)
	ssoextAssertPanic(t, "duplicate", func() { RegisterLDAPAuthenticators("ldap-dup", good) })
}
