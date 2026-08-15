package ssoext

import (
	"context"
	"net/http"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/registrar"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// KerberosServerDeps is the dependency bundle a KerberosHandlerFactory
// receives. Every field is a stdlib type or an intra-repo SDK type — there is
// NO gokrb5 type here, so an operator can register a Kerberos handler factory
// from their forked binary WITHOUT github.com/jcmturner/gokrb5/v8 (and its
// asn1/crypto transitive deps) entering this module's go.mod (the firm
// zero-external-dep invariant; the factory closes over its own keytab/gokrb5
// types in the operator's module). It mirrors SAMLServerDeps: exactly the
// seams the WebAuthn/SAML mint paths consume, so a Kerberos login lands on
// the one identity model with the one token-signing key per tenant.
//
//   - ClientStore / SessionManager / UserProvider are the same stores the
//     rest of the server reads, so a validated principal upserts onto the one
//     identity model and its session carries the same lifecycle.
//   - IssuerForClient resolves the per-tenant access-token issuer for the
//     minting client, so a Kerberos-minted token is signed with the SAME key
//     as that client's tokens from /auth/login + /token.
//   - IDTokenIssuerForClient / EncryptIDToken OPTIONALLY mint an id_token
//     through the tenant's key + JWE response-encryption path. Both nil ⇒ no
//     id_token is ever minted (the access token + session still mint) —
//     byte-identical to an id_token-less build.
//   - AuditRecorder records login_success / login_failure on the SAME
//     recorder the built-in flows use. Nil when audit is disabled.
//   - Logger is the server logger (never nil at the cmd call site).
type KerberosServerDeps struct {
	// ClientStore resolves the minting client at request time (so an
	// inactive/deleted client fails the mint, never a stale cache). REQUIRED.
	ClientStore sso.ClientStore

	// SessionManager creates the SSO session the minted tokens anchor to,
	// through the manager (NOT a raw store) so a Kerberos login lands with the
	// same expiry/refresh/revoke lifecycle as every other login. REQUIRED.
	SessionManager sso.SessionManager

	// UserProvider upserts the validated principal onto the one identity model.
	// REQUIRED.
	UserProvider sso.UserProvider

	// IssuerForClient is the server's per-tenant ACCESS-token issuer selector
	// (tenant -> client strategy -> default). REQUIRED.
	IssuerForClient func(c *sso.Client) (string, sso.TokenIssuer, error)

	// IDTokenIssuerForClient OPTIONALLY selects the per-tenant id_token issuer
	// so a Kerberos-minted id_token (when the client requests the openid
	// scope) is signed by the tenant's key. Nil ⇒ no id_token is ever minted.
	IDTokenIssuerForClient func(c *sso.Client) (oidc.IDTokenIssuer, bool, error)

	// EncryptIDToken OPTIONALLY routes a freshly-signed id_token through the
	// server's JWE response-encryption path (fail-closed: returns ("", false)
	// when the client opted into encryption but it failed, so the caller omits
	// the id_token rather than leak cleartext). Nil ⇒ the signed token passes
	// through. Only consulted when an id_token is minted.
	EncryptIDToken func(ctx context.Context, client *sso.Client, signed string) (string, bool)

	// AuditRecorder OPTIONALLY records a login_success (provider = Config.Name)
	// per minted token on the SAME pipeline the rest of the server uses. Nil ⇒
	// no audit event (the mint still succeeds).
	AuditRecorder *audit.Recorder

	// Logger is the server logger. Nil ⇒ a no-op logger. The handler logs
	// validation failures (reason only, never the keytab or the token bytes)
	// and mint failures here.
	Logger spi.Logger
}

// KerberosHandler is one HTTP route a KerberosHandlerFactory contributes (the
// SPNEGO/Negotiate endpoint). The fork mounts each via *sso.Server.Handle so
// they share the built-in middleware stack.
type KerberosHandler struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// KerberosHandlerSet is everything a KerberosHandlerFactory produces: the
// HTTP routes, and an optional readiness probe (e.g. keytab freshness / KDC
// reachability) the fork wires into /readyz. Handlers / ReadyCheck may be
// empty/nil.
type KerberosHandlerSet struct {
	Handlers   []KerberosHandler
	ReadyCheck func(ctx context.Context) error
}

// KerberosHandlerFactory builds the Kerberos/SPNEGO surface from the server
// dependencies. It is called once at boot; a returned error fails boot
// closed. The operator implements this in their forked module (where gokrb5 +
// the keytab live) and registers it via RegisterKerberosHandlers.
type KerberosHandlerFactory func(ctx context.Context, deps KerberosServerDeps) (*KerberosHandlerSet, error)

// KerberosHandlerRegistry holds operator-registered Kerberos handler
// factories. The Kerberos SDK (github.com/jcmturner/gokrb5/v8 and its
// asn1/crypto transitive deps) lives in the operator's forked binary, not
// this module — the operator calls RegisterKerberosHandlers from their main
// before running the server, then selects the factory by name from their own
// config. The generic machinery is the standard platform/registrar
// implementation (same shape as SAMLHandlerRegistry). Exported so tests can
// clean up between runs via Unregister.
var KerberosHandlerRegistry = registrar.New[KerberosHandlerFactory]()

// RegisterKerberosHandlers registers a Kerberos handler factory under name.
// Intended to be called from an operator's forked main during init/startup.
// Panics on an empty name, a nil factory, or a duplicate name (all
// unrecoverable wiring mistakes) — identical to
// serverbuildsign.RegisterExternalSigner and RegisterSAMLHandlers.
func RegisterKerberosHandlers(name string, f KerberosHandlerFactory) {
	KerberosHandlerRegistry.Register(name, f)
}

// LookupKerberosHandlerFactory returns the factory registered under name.
func LookupKerberosHandlerFactory(name string) (KerberosHandlerFactory, bool) {
	return KerberosHandlerRegistry.Lookup(name)
}

// RegisteredKerberosHandlers returns the sorted names of all registered
// Kerberos factories, for the boot-time diagnostic when a config names an
// unregistered factory.
func RegisteredKerberosHandlers() []string {
	return KerberosHandlerRegistry.Names()
}
