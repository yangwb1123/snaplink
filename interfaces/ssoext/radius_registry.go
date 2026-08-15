package ssoext

import (
	"context"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/registrar"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// RADIUSServerDeps is the dependency bundle a RADIUSAuthenticatorFactory
// receives. Every field is a stdlib type or an intra-repo SDK type — there is
// NO layeh.com/radius type here, so an operator can register a RADIUS
// authenticator factory from their forked binary WITHOUT the RADIUS SDK
// entering this module's go.mod (the firm zero-external-dep invariant; the
// factory closes over its own layeh types in the operator's module). It
// mirrors how SAMLServerDeps keeps crewjam/saml out of this module and
// serverbuildsign.ExternalSignerFactory keeps the vendor KMS SDK in the
// operator's main.
//
// The factory gets the server seams a RADIUS/NPS-auth surface needs to land on
// the one identity model: Logger carries operational failures (server
// unreachable, RadSec handshake failure, a non-authentic reply) to the
// server's log pipeline — never credentials or the verdict of a credential
// check, which would be an enumeration oracle. The RADIUS Config itself
// (Servers, SharedSecret, protocol) is NOT part of this struct: it is the
// operator's own config, closed over in their factory, so the layeh types it
// would drag in stay in the operator's module.
type RADIUSServerDeps struct {
	// Logger is the server logger (never nil at the cmd call site). The
	// factory plumbs it into the authenticator's WithLogger option so
	// operational failures surface in the same log pipeline as the built-in
	// flows.
	Logger spi.Logger
}

// RADIUSAuthenticatorSet is everything a RADIUSAuthenticatorFactory produces:
// the sso.Authenticator(s) to register on the server (so
// /auth/login?provider=<name> drives the RADIUS flow), and an optional
// readiness probe (e.g. server reachability) the fork wires into /readyz.
// Authenticators / ReadyCheck may be empty/nil.
type RADIUSAuthenticatorSet struct {
	Authenticators []sso.Authenticator
	ReadyCheck     func(ctx context.Context) error
}

// RADIUSAuthenticatorFactory builds the RADIUS surface from the server
// dependencies. It is called once at boot; a returned error fails boot
// closed. The operator implements this in their forked module (where
// layeh.com/radius lives) and registers it via RegisterRADIUSAuthenticators.
type RADIUSAuthenticatorFactory func(ctx context.Context, deps RADIUSServerDeps) (*RADIUSAuthenticatorSet, error)

// RADIUSAuthenticatorRegistry holds operator-registered RADIUS authenticator
// factories. The RADIUS SDK (layeh.com/radius) lives in the operator's forked
// binary, not this module — the operator calls RegisterRADIUSAuthenticators
// from their main before running the server, then selects the factory by name
// from their own config. The generic machinery is the standard
// platform/registrar implementation (same shape as SAMLHandlerRegistry /
// serverbuildsign.RegisterExternalSigner). Exported so tests can clean up
// between runs via Unregister.
var RADIUSAuthenticatorRegistry = registrar.New[RADIUSAuthenticatorFactory]()

// RegisterRADIUSAuthenticators registers a RADIUS authenticator factory under
// name. Intended to be called from an operator's forked main during
// init/startup. Panics on an empty name, a nil factory, or a duplicate name
// (all unrecoverable wiring mistakes) — identical to
// serverbuildsign.RegisterExternalSigner and RegisterSAMLHandlers.
func RegisterRADIUSAuthenticators(name string, f RADIUSAuthenticatorFactory) {
	RADIUSAuthenticatorRegistry.Register(name, f)
}

// LookupRADIUSAuthenticatorFactory returns the factory registered under name.
func LookupRADIUSAuthenticatorFactory(name string) (RADIUSAuthenticatorFactory, bool) {
	return RADIUSAuthenticatorRegistry.Lookup(name)
}

// RegisteredRADIUSAuthenticators returns the sorted names of all registered
// RADIUS factories, for the boot-time diagnostic when a config names an
// unregistered factory.
func RegisteredRADIUSAuthenticators() []string {
	return RADIUSAuthenticatorRegistry.Names()
}
