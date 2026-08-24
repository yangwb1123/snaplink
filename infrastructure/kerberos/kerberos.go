// Package kerberosauth implements a Kerberos/SPNEGO (Windows Integrated
// Authentication / desktop SSO) authenticator for snaplink/sso as a SEPARATE
// nested Go module. See doc.go for the package overview + the operator-fork
// wiring guide.
package kerberosauth

import (
	"errors"
	"net/http"

	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Deps is the ROOT-module-typed dependency bundle Build needs. Every field is
// a stdlib type, an sso (root-module) type, an oidc type, or an spi type —
// there is NO cmd/sso-server (package main) type here, because a separate
// module's package cannot import package main. The operator's forked main
// constructs a Deps from its own server accessors inside the factory (see the
// package doc for the copy-pasteable wiring). Mirrors saml.Deps.
//
// Deps EMBEDS the standard host-API bundle (interfaces/ssoext.
// KerberosServerDeps — the exact seams the stock server hands a registered
// Kerberos handler factory). Embedding (not aliasing) keeps every existing
// field name: a fork's factory receives ssoext.KerberosServerDeps from
// ssoext.RegisterKerberosHandlers and constructs
// `kerberosauth.Deps{KerberosServerDeps: d, ...}` with no field-for-field
// copy — see the package doc for the copy-pasteable adaptation.
type Deps struct {
	// KerberosServerDeps carries the root-module-typed seams the server passes
	// a registered Kerberos handler factory (ClientStore / SessionManager /
	// UserProvider, IssuerForClient, IDTokenIssuerForClient, EncryptIDToken,
	// AuditRecorder, Logger).
	ssoext.KerberosServerDeps
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
