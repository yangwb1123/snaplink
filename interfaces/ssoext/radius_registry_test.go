package ssoext

import (
	"context"
	"testing"
)

// registerRADIUSAuthenticatorsForTest registers a RADIUS factory and
// unregisters it when the test ends, keeping the package-global registry
// clean across subtests and -count>1 runs. RegisterRADIUSAuthenticators
// panics on a duplicate name by design (a production wiring guard), so tests
// must clean up rather than relax it — mirrors registerSAMLHandlersForTest.
func registerRADIUSAuthenticatorsForTest(t *testing.T, name string, f RADIUSAuthenticatorFactory) {
	t.Helper()
	RegisterRADIUSAuthenticators(name, f)
	t.Cleanup(func() {
		RADIUSAuthenticatorRegistry.Unregister(name)
	})
}

func TestRegisterRADIUSAuthenticators_RegisterLookupList(t *testing.T) {
	t.Parallel()
	factory := func(context.Context, RADIUSServerDeps) (*RADIUSAuthenticatorSet, error) {
		return &RADIUSAuthenticatorSet{}, nil
	}
	registerRADIUSAuthenticatorsForTest(t, "radius-a", factory)
	registerRADIUSAuthenticatorsForTest(t, "radius-b", factory)

	if _, ok := LookupRADIUSAuthenticatorFactory("radius-a"); !ok {
		t.Error("LookupRADIUSAuthenticatorFactory(radius-a) = not found, want found")
	}
	if _, ok := LookupRADIUSAuthenticatorFactory("radius-missing"); ok {
		t.Error("LookupRADIUSAuthenticatorFactory(radius-missing) = found, want not found")
	}

	names := RegisteredRADIUSAuthenticators()
	// Sorted output; both registered names present.
	if len(names) < 2 || names[0] != "radius-a" || names[1] != "radius-b" {
		t.Errorf("RegisteredRADIUSAuthenticators() = %v, want [radius-a radius-b ...] sorted", names)
	}
}

func TestRegisterRADIUSAuthenticators_RejectsBadInput(t *testing.T) {
	t.Parallel()
	good := func(context.Context, RADIUSServerDeps) (*RADIUSAuthenticatorSet, error) {
		return &RADIUSAuthenticatorSet{}, nil
	}
	// ssoextAssertPanic is defined in saml_registry_test.go (same package).
	ssoextAssertPanic(t, "empty name", func() { RegisterRADIUSAuthenticators("", good) })
	ssoextAssertPanic(t, "nil factory", func() { RegisterRADIUSAuthenticators("radius-nilfac", nil) })

	registerRADIUSAuthenticatorsForTest(t, "radius-dup", good)
	ssoextAssertPanic(t, "duplicate", func() { RegisterRADIUSAuthenticators("radius-dup", good) })
}
