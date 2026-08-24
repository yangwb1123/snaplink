package ldapauth

import (
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoext"
)

// Deps is the ROOT-module-typed dependency bundle Build needs. Every field is
// a stdlib type or a root-module type — there is NO cmd/sso-server (package
// main) type here, because a separate module's package cannot import package
// main. The operator's forked main (which DOES have cmd's LDAPServerDeps)
// constructs a Deps from its LDAPServerDeps fields inside the factory closure
// (see the package doc for the copy-pasteable adaptation).
//
// Deps EMBEDS the standard host-API bundle (interfaces/ssoext.LDAPServerDeps
// — the exact seams the stock server hands a registered LDAP authenticator
// factory). Embedding (not aliasing) keeps every existing field name: a
// fork's factory receives ssoext.LDAPServerDeps from
// ssoext.RegisterLDAPAuthenticators and constructs
// `ldapauth.Deps{LDAPServerDeps: d}` with no field-for-field copy — mirroring
// saml.Deps.
type Deps struct {
	// LDAPServerDeps carries the root-module-typed seams the server passes a
	// registered LDAP authenticator factory (Logger — the authenticator
	// records operational failures here, never credentials or verdicts).
	ssoext.LDAPServerDeps
}

// BuildResult is everything Build produces: the sso.Authenticator(s) the
// operator registers (so /auth/login?provider=<name> drives the directory
// flow). The operator adapts this onto ssoext.LDAPAuthenticatorSet.
type BuildResult struct {
	Authenticators []sso.Authenticator
}

// Build validates cfg and constructs the directory authenticator, plumbing
// the host-API Logger onto it via WithLogger. A construction error (invalid
// TLS posture, filter missing its placeholder) fails the operator's boot
// CLOSED — it performs NO network I/O, exactly like New, so a directory that
// is down at boot does not block startup. opts pass straight through to New
// (e.g. an operator-supplied dialer override in a fork that needs one).
func Build(deps Deps, cfg Config, opts ...Option) (*BuildResult, error) {
	if deps.Logger != nil {
		opts = append(opts, WithLogger(deps.Logger))
	}
	auth, err := New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	return &BuildResult{Authenticators: []sso.Authenticator{auth}}, nil
}
