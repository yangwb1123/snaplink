package ssoext

import (
	"context"
	"testing"
)

// registerKerberosHandlersForTest registers a Kerberos factory and
// unregisters it when the test ends, keeping the package-global registry
// clean across subtests and -count>1 runs. RegisterKerberosHandlers panics on
// a duplicate name by design (a production wiring guard), so tests must clean
// up rather than relax it — mirrors registerSAMLHandlersForTest.
func registerKerberosHandlersForTest(t *testing.T, name string, f KerberosHandlerFactory) {
	t.Helper()
	RegisterKerberosHandlers(name, f)
	t.Cleanup(func() {
		KerberosHandlerRegistry.Unregister(name)
	})
}

func TestRegisterKerberosHandlers_RegisterLookupList(t *testing.T) {
	t.Parallel()
	factory := func(context.Context, KerberosServerDeps) (*KerberosHandlerSet, error) {
		return &KerberosHandlerSet{}, nil
	}
	registerKerberosHandlersForTest(t, "kerberos-a", factory)
	registerKerberosHandlersForTest(t, "kerberos-b", factory)

	if _, ok := LookupKerberosHandlerFactory("kerberos-a"); !ok {
		t.Error("LookupKerberosHandlerFactory(kerberos-a) = not found, want found")
	}
	if _, ok := LookupKerberosHandlerFactory("kerberos-missing"); ok {
		t.Error("LookupKerberosHandlerFactory(kerberos-missing) = found, want not found")
	}

	names := RegisteredKerberosHandlers()
	// Sorted output; both registered names present.
	if len(names) < 2 || names[0] != "kerberos-a" || names[1] != "kerberos-b" {
		t.Errorf("RegisteredKerberosHandlers() = %v, want [kerberos-a kerberos-b ...] sorted", names)
	}
}

func TestRegisterKerberosHandlers_RejectsBadInput(t *testing.T) {
	t.Parallel()
	good := func(context.Context, KerberosServerDeps) (*KerberosHandlerSet, error) {
		return &KerberosHandlerSet{}, nil
	}
	// ssoextAssertPanic is defined in saml_registry_test.go (same package).
	ssoextAssertPanic(t, "empty name", func() { RegisterKerberosHandlers("", good) })
	ssoextAssertPanic(t, "nil factory", func() { RegisterKerberosHandlers("kerberos-nilfac", nil) })

	registerKerberosHandlersForTest(t, "kerberos-dup", good)
	ssoextAssertPanic(t, "duplicate", func() { RegisterKerberosHandlers("kerberos-dup", good) })
}
