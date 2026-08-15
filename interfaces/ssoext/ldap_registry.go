package ssoext

import (
	"context"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/registrar"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// LDAPServerDeps is the dependency bundle an LDAPAuthenticatorFactory
// receives. Every field is a stdlib type or an intra-repo SDK type — there is
// NO go-ldap type here, so an operator can register an LDAP authenticator
// factory from their forked binary WITHOUT github.com/go-ldap/ldap/v3 (and its
// asn1-ber transitive dep) entering this module's go.mod (the firm
// zero-external-dep invariant; the factory closes over its own go-ldap types
// in the operator's module). It mirrors how SAMLServerDeps keeps crewjam/saml
// out of this module and serverbuildsign.ExternalSignerFactory keeps the
// vendor KMS SDK in the operator's main.
//
// The factory gets the server seams a directory-auth surface needs to land on
// the one identity model: Logger carries operational failures (unreachable
// directory, TLS upgrade failure) to the server's log pipeline — never
// credentials or the verdict of a credential check, which would be an
// enumeration oracle. The LDAP Config itself (URLs, BindDN, filters,
// attribute mapping) is NOT part of this struct: it is the operator's own
// config, closed over in their factory, so the go-ldap types it would drag in
// stay in the operator's module.
type LDAPServerDeps struct {
	// Logger is the server logger (never nil at the cmd call site). The
	// factory plumbs it into the authenticator's WithLogger option so
	// operational failures surface in the same log pipeline as the built-in
	// flows.
	Logger spi.Logger
}

// LDAPAuthenticatorSet is everything an LDAPAuthenticatorFactory produces:
// the sso.Authenticator(s) to register on the server (so
// /auth/login?provider=<name> drives the directory flow), and an optional
// readiness probe (e.g. directory reachability) the fork wires into /readyz.
// Authenticators / ReadyCheck may be empty/nil.
type LDAPAuthenticatorSet struct {
	Authenticators []sso.Authenticator
	ReadyCheck     func(ctx context.Context) error
}

// LDAPAuthenticatorFactory builds the LDAP surface from the server
// dependencies. It is called once at boot; a returned error fails boot
// closed. The operator implements this in their forked module (where go-ldap
// lives) and registers it via RegisterLDAPAuthenticators.
type LDAPAuthenticatorFactory func(ctx context.Context, deps LDAPServerDeps) (*LDAPAuthenticatorSet, error)

// LDAPAuthenticatorRegistry holds operator-registered LDAP authenticator
// factories. The LDAP SDK (github.com/go-ldap/ldap/v3, its asn1-ber transitive
// dep) lives in the operator's forked binary, not this module — the operator
// calls RegisterLDAPAuthenticators from their main before running the server,
// then selects the factory by name from their own config. The generic
// machinery is the standard platform/registrar implementation (same shape as
// SAMLHandlerRegistry / serverbuildsign.RegisterExternalSigner). Exported so
// tests can clean up between runs via Unregister.
var LDAPAuthenticatorRegistry = registrar.New[LDAPAuthenticatorFactory]()

// RegisterLDAPAuthenticators registers an LDAP authenticator factory under
// name. Intended to be called from an operator's forked main during
// init/startup. Panics on an empty name, a nil factory, or a duplicate name
// (all unrecoverable wiring mistakes) — identical to
// serverbuildsign.RegisterExternalSigner and RegisterSAMLHandlers.
func RegisterLDAPAuthenticators(name string, f LDAPAuthenticatorFactory) {
	LDAPAuthenticatorRegistry.Register(name, f)
}

// LookupLDAPAuthenticatorFactory returns the factory registered under name.
func LookupLDAPAuthenticatorFactory(name string) (LDAPAuthenticatorFactory, bool) {
	return LDAPAuthenticatorRegistry.Lookup(name)
}

// RegisteredLDAPAuthenticators returns the sorted names of all registered LDAP
// factories, for the boot-time diagnostic when a config names an unregistered
// factory.
func RegisteredLDAPAuthenticators() []string {
	return LDAPAuthenticatorRegistry.Names()
}
