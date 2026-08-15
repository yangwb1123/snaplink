// Package ssoext is the operator-extension host API for the stock server:
// the typed, name-addressed registrars a forked binary uses to plug in
// surfaces whose heavy dependencies (SAML/XML/DSig, the LDAP/Kerberos/RADIUS
// stacks, vendor KMS SDKs) must stay out of the core module's go.mod. The
// registrars themselves live here — OUTSIDE cmd — so a fork imports the types
// instead of re-declaring them, and the generic machinery is the single
// standard implementation in platform/registrar. The cmd-owned SAML registry
// is consumed by mountSAMLHandler (saml.handler); the authenticator-family
// registries (LDAP/Kerberos/RADIUS) are consumed by the operator's own boot
// composition, because stock config deliberately has no ldap/kerberos/radius
// sections — those surfaces are fork-binary integrations only.
//
// Registration is process-local and name-addressed by configuration
// (saml.handler selects a factory by name at boot). It is the in-process
// compile-time seam for forked binaries only — NOT a hot-plugin registry:
// nothing here can add entries after startup, and installable third-party
// code must run out of process over the typed authenticated protocol (see
// docs/plugin-system.md).
package ssoext

import (
	"context"
	"net/http"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/registrar"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// SAMLServerDeps is the dependency bundle a SAMLHandlerFactory receives.
// Every field is a stdlib type or an intra-repo SDK type — there is NO
// SAML/XML/crewjam type here, so an operator can register a SAML factory
// from their forked binary WITHOUT the SAML SDK entering this module's
// go.mod (the firm zero-external-dep invariant; the factory closes over its
// own crewjam types in the operator's module). It mirrors how
// serverbuildsign.ExternalSignerFactory keeps the vendor KMS SDK in the
// operator's main.
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

	// ResumeFederatedLogin hands a validated SAML assertion back to the
	// server-owned OAuth authorization transaction. It returns false only for
	// legacy ACS requests that did not originate at /auth/login.
	ResumeFederatedLogin func(http.ResponseWriter, *http.Request, string, *sso.AuthResult) bool
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

// SAMLHandlerRegistry holds operator-registered SAML handler factories. The
// SAML SDK (crewjam/saml, encoding/xml DSig, etc.) lives in the operator's
// forked binary, not this module — the operator calls RegisterSAMLHandlers
// from their main before running the server, then selects the factory by
// name via saml.handler. The generic machinery is the standard
// platform/registrar implementation (same shape as
// serverbuildsign.RegisterExternalSigner). Exported so tests can clean up
// between runs via Unregister.
var SAMLHandlerRegistry = registrar.New[SAMLHandlerFactory]()

// RegisterSAMLHandlers registers a SAML handler factory under name,
// reachable via saml.handler. Intended to be called from an operator's
// forked main during init/startup. Panics on an empty name, a nil factory,
// or a duplicate name (all unrecoverable wiring mistakes) — identical to
// serverbuildsign.RegisterExternalSigner.
func RegisterSAMLHandlers(name string, f SAMLHandlerFactory) {
	SAMLHandlerRegistry.Register(name, f)
}

// LookupSAMLHandlerFactory returns the factory registered under name.
func LookupSAMLHandlerFactory(name string) (SAMLHandlerFactory, bool) {
	return SAMLHandlerRegistry.Lookup(name)
}

// RegisteredSAMLHandlers returns the sorted names of all registered SAML
// factories, for the boot-time diagnostic when saml.handler names an
// unregistered factory.
func RegisteredSAMLHandlers() []string {
	return SAMLHandlerRegistry.Names()
}
