// Package kerberosauth implements a Kerberos/SPNEGO (Windows Integrated
// Authentication / desktop SSO) authenticator for snaplink/sso as a SEPARATE
// nested Go module. See doc.go for the package overview + the operator-fork
// wiring guide.
package kerberosauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/spi"
)

// Deps is the ROOT-module-typed dependency bundle Build needs. Every field is
// a stdlib type, an sso (root-module) type, an oidc type, or an spi type —
// there is NO cmd/sso-server (package main) type here, because a separate
// module's package cannot import package main. The operator's forked main
// constructs a Deps from its own server accessors inside the factory (see the
// package doc for the copy-pasteable wiring). Mirrors saml.Deps.
type Deps struct {
	// ClientStore resolves the configured ClientID to the live sso.Client at
	// request time (so an inactive/deleted client fails the mint, never a stale
	// cache). REQUIRED.
	ClientStore sso.ClientStore

	// SessionManager creates the SSO session the minted tokens anchor to —
	// through the manager (NOT a raw store) so a Kerberos login lands with the
	// same expiry/refresh/revoke lifecycle as every other login. REQUIRED.
	SessionManager sso.SessionManager

	// UserProvider upserts the validated principal onto the one identity model
	// (CreateOrUpdate), exactly as the SAML ACS + the login orchestrator do.
	// REQUIRED.
	UserProvider sso.UserProvider

	// IssuerForClient is the server's per-tenant ACCESS-token issuer selector
	// (tenant -> client strategy -> default). The handler resolves the minting
	// client's issuer through it so a Kerberos-minted access token is signed
	// with the SAME key as that tenant's tokens from /auth/login + /token —
	// closing the per-tenant-signing surface the WebAuthn + SAML paths already
	// close. REQUIRED. Set it to *sso.Server.IssuerForClient.
	IssuerForClient func(c *sso.Client) (string, sso.TokenIssuer, error)

	// IDTokenIssuerForClient OPTIONALLY selects the per-tenant id_token issuer
	// so a Kerberos-minted id_token (when the client requests the openid scope)
	// is signed by the tenant's key. Mirrors the server's fail-closed selector:
	// err != nil ⇒ a misconfigured/unregistered tenant issuer (the mint fails
	// closed rather than sign with the shared key); emit=false ⇒ the tenant
	// strategy can't mint id_tokens (omit). Nil ⇒ no id_token is ever minted
	// (the access token + session still mint) — byte-identical to an
	// id_token-less build. Set it to *sso.Server.IDTokenIssuerForClient.
	IDTokenIssuerForClient func(c *sso.Client) (oidc.IDTokenIssuer, bool, error)

	// EncryptIDToken OPTIONALLY routes a freshly-signed id_token through the
	// server's JWE response-encryption path (fail-closed: returns ("", false)
	// when the client opted into encryption but it failed, so the caller omits
	// the id_token rather than leak cleartext). Nil ⇒ no encryption layer (the
	// signed token passes through). Set it to
	// *sso.Server.EncryptIDTokenForClient. Only consulted when an id_token is
	// minted.
	EncryptIDToken func(ctx context.Context, client *sso.Client, signed string) (string, bool)

	// AuditRecorder OPTIONALLY records a login_success (provider = Config.Name,
	// AMR krb5) per minted token on the SAME pipeline the rest of the server
	// uses. Nil ⇒ no audit event (the mint still succeeds). Mirrors the SAML
	// IdP's recordAssertion.
	AuditRecorder *audit.Recorder

	// Logger is the server logger. Nil ⇒ a no-op logger. The handler logs
	// validation failures (reason only, never the keytab or the token bytes)
	// and mint failures here.
	Logger spi.Logger
}

// HandlerSpec is the single HTTP route Build contributes — the Negotiate
// handler. It mirrors saml.HandlerSpec field-for-field so the operator maps it
// onto cmd's handler-registry type trivially and mounts it via
// *sso.Server.Handle (sharing the built-in middleware stack).
//
// Method is GET: SPNEGO/Negotiate is a browser-driven GET handshake (the
// browser retries the SAME GET with the ticket after the 401 challenge). The
// handler also tolerates POST for non-browser clients that prefer it.
type HandlerSpec struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// BuildResult is everything Build produces: the HTTP route(s) the operator's
// fork mounts. Unlike the SAML/LDAP authenticator results it carries NO
// sso.Authenticator — SPNEGO is a Negotiate-header flow, not a username/
// password sso.Authenticator, so it is a mounted handler only (like WebAuthn's
// ceremony + the SAML IdP handlers).
type BuildResult struct {
	Handlers []HandlerSpec
}

// Build wires the Negotiate handler for one Kerberos/SPNEGO surface and
// returns it as an importable root-typed HandlerSpec for the operator's fork
// to mount. A construction error (bad config, missing required dep) fails the
// operator's boot CLOSED.
//
// The validator is supplied by the caller (typically NewGokrb5Validator(cfg)
// in the operator's fork) so this function stays free of any KDC/keytab I/O and
// the tests inject a fake. validator MUST NOT be nil — without it there is
// nothing to validate SPNEGO tokens against (every token would have to be
// trusted blindly).
func Build(deps Deps, cfg Config, validator SPNEGOValidator) (*BuildResult, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if validator == nil {
		return nil, errors.New("kerberos: validator required (the keytab-backed SPNEGO validator is the trust anchor)")
	}
	if deps.ClientStore == nil {
		return nil, errors.New("kerberos: ClientStore required")
	}
	if deps.SessionManager == nil {
		return nil, errors.New("kerberos: SessionManager required (the handler creates the SSO session)")
	}
	if deps.UserProvider == nil {
		return nil, errors.New("kerberos: UserProvider required (the handler upserts the principal)")
	}
	if deps.IssuerForClient == nil {
		return nil, errors.New("kerberos: IssuerForClient required (per-tenant access-token signing)")
	}

	logger := deps.Logger
	if logger == nil {
		logger = spi.NopLogger{}
	}

	h := &negotiateHandler{
		cfg:       cfg,
		validator: validator,
		deps:      deps,
		logger:    logger,
	}

	path := cfg.mountPath()
	return &BuildResult{
		Handlers: []HandlerSpec{
			// SPNEGO is a browser GET handshake; also accept POST for
			// programmatic clients. Both run the identical flow.
			{Method: http.MethodGet, Path: path, Handler: h.serve},
			{Method: http.MethodPost, Path: path, Handler: h.serve},
		},
	}, nil
}
