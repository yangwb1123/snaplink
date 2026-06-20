package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/spi"
)

// SAMLServerDeps is the dependency bundle a SAMLHandlerFactory receives.
// Every field is a stdlib type or an intra-repo SDK type — there is NO
// SAML/XML/crewjam type here, so an operator can register a SAML factory
// from their forked binary WITHOUT the SAML SDK entering this module's
// go.mod (the firm zero-external-dep invariant; the factory closes over its
// own crewjam types in the operator's module). It mirrors how
// ExternalSignerFactory keeps the vendor KMS SDK in the operator's main.
//
// The factory gets exactly what a SAML SP/IdP surface needs to mint tokens
// the same way the rest of the server does:
//
//   - IssuerForClient is the server's per-tenant access-token selector
//     (tenant -> client strategy -> default), so a SAML-minted token is
//     signed with the same key as that client's tokens elsewhere.
//   - Issuer is the AS issuer URL (stamped into tokens / metadata).
//   - RegisterAuthenticator registers the SP-side SAML Authenticator at boot
//     so the standard /auth/login + callback machinery can drive it.
//
// The signing KEY itself is borrowed separately, off the JWT issuer's
// CryptoSigner() accessor (a stdlib crypto.Signer for XML-DSig), which the
// operator's factory reaches via the issuer it resolves through
// IssuerForClient — kept off this struct so the seam stays generic (a
// crypto.Signer, not a SAML signer).
type SAMLServerDeps struct {
	// IssuerForClient resolves the per-tenant access-token issuer for a
	// client, matching the server's resolution order + fail-closed contract
	// (err != nil ⇒ a misconfigured/unregistered tenant issuer). The
	// factory uses it both to mint tokens and — via a type assertion to the
	// CryptoSigner() accessor on defaultimpl's issuers — to borrow the
	// signing key as a stdlib crypto.Signer for XML-DSig.
	IssuerForClient func(c *sso.Client) (string, sso.TokenIssuer, error)

	// ClientStore / SessionManager / UserProvider are the same stores the
	// rest of the server reads, so a SAML login lands on one identity model.
	ClientStore    sso.ClientStore
	SessionManager sso.SessionManager
	UserProvider   sso.UserProvider

	// Issuer is the configured AS issuer URL.
	Issuer string

	// AuditRecorder is the shared audit pipeline — a SAML SP/IdP records
	// login + assertion events on the SAME recorder (hash chain, sinks) the
	// built-in flows use. Nil when audit is disabled.
	AuditRecorder *audit.Recorder

	// Logger is the server logger (never nil at the cmd call site).
	Logger spi.Logger

	// RegisterAuthenticator installs the SP-side SAML Authenticator on the
	// running server post-construction (mirrors *sso.Server.RegisterAuthenticator).
	// The factory returns its authenticators in the handler set for cmd to
	// register; this hook lets a factory register additional ones itself if
	// it must (kept symmetric with the webauthn/SP plumbing).
	RegisterAuthenticator func(a sso.Authenticator)
}

// SAMLHandler is one HTTP route a SAMLHandlerFactory contributes (e.g. the
// SP metadata endpoint, the ACS callback). cmd mounts each via
// *sso.Server.Handle so they share the built-in middleware stack.
type SAMLHandler struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// SAMLHandlerSet is everything a SAMLHandlerFactory produces: the HTTP
// routes, any SP-side Authenticators to register, and an optional readiness
// probe (e.g. IdP-metadata freshness / backing-store reachability) cmd
// wires into /readyz. Authenticators / ReadyCheck may be empty/nil.
type SAMLHandlerSet struct {
	Handlers       []SAMLHandler
	Authenticators []sso.Authenticator
	ReadyCheck     func(ctx context.Context) error
}

// SAMLHandlerFactory builds the SAML surface from the server dependencies.
// It is called once at boot; a returned error fails boot closed. The
// operator implements this in their forked module (where crewjam lives) and
// registers it via RegisterSAMLHandlers.
type SAMLHandlerFactory func(ctx context.Context, deps SAMLServerDeps) (*SAMLHandlerSet, error)

// samlHandlerRegistry holds operator-registered SAML handler factories. The
// SAML SDK (crewjam/saml, encoding/xml DSig, etc.) lives in the operator's
// forked binary, not this module — the operator calls RegisterSAMLHandlers
// from their main before running the server, then selects the factory by
// name via saml.handler. This mirrors externalSignerRegistry EXACTLY (which
// keeps the vendor KMS SDK out of the SPI the same way).
var samlHandlerRegistry = struct {
	mu        sync.RWMutex
	factories map[string]SAMLHandlerFactory
}{factories: map[string]SAMLHandlerFactory{}}

// RegisterSAMLHandlers registers a SAML handler factory under name,
// reachable via saml.handler. Intended to be called from an operator's
// forked main during init/startup. Panics on an empty name, a nil factory,
// or a duplicate name (all unrecoverable wiring mistakes) — identical to
// RegisterExternalSigner.
func RegisterSAMLHandlers(name string, f SAMLHandlerFactory) {
	if name == "" {
		panic("RegisterSAMLHandlers: empty name")
	}
	if f == nil {
		panic(fmt.Sprintf("RegisterSAMLHandlers: nil factory for %q", name))
	}
	samlHandlerRegistry.mu.Lock()
	defer samlHandlerRegistry.mu.Unlock()
	if _, dup := samlHandlerRegistry.factories[name]; dup {
		panic(fmt.Sprintf("RegisterSAMLHandlers: %q already registered", name))
	}
	samlHandlerRegistry.factories[name] = f
}

// lookupSAMLHandlerFactory returns the factory registered under name.
func lookupSAMLHandlerFactory(name string) (SAMLHandlerFactory, bool) {
	samlHandlerRegistry.mu.RLock()
	defer samlHandlerRegistry.mu.RUnlock()
	f, ok := samlHandlerRegistry.factories[name]
	return f, ok
}

// RegisteredSAMLHandlers returns the sorted names of all registered SAML
// factories, for the boot-time diagnostic when saml.handler names an
// unregistered factory.
func RegisteredSAMLHandlers() []string {
	samlHandlerRegistry.mu.RLock()
	defer samlHandlerRegistry.mu.RUnlock()
	names := make([]string, 0, len(samlHandlerRegistry.factories))
	for n := range samlHandlerRegistry.factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
