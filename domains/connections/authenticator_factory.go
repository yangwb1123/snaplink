package connections

import (
	"context"
	"errors"

	"github.com/yangwb1123/snaplink/shared/core"
)

// authenticator_factory.go is the runtime seam between the connection MODEL
// (this package) and the upstream-authenticator MACHINERY (the composition
// root): AuthenticatorFactory turns a resolved Connection into a live
// core.Authenticator the /auth/login flow can dispatch to, exactly like a
// statically-registered provider. The interface lives HERE (not in the
// consumer) so both the interfaces/sso dispatch code and the cmd factory
// implementation depend downward on the same seam; this package still carries
// no OIDC/SAML dependency — implementations interpret Connection.Config.

// Connection.Config keys the runtime AuthenticatorFactory reads for a
// TypeOIDC connection, extending the probe's ConfigKeyOIDCIssuer /
// ConfigKeySAMLMetadataURL set. Endpoints are explicit (no discovery fetch on
// the login path): the admin resolves them once when creating the connection.
const (
	ConfigKeyOIDCAuthorizationEndpoint = "oidc_authorization_endpoint"
	ConfigKeyOIDCTokenEndpoint         = "oidc_token_endpoint"
	ConfigKeyOIDCUserinfoEndpoint      = "oidc_userinfo_endpoint"
	ConfigKeyOIDCClientID              = "oidc_client_id"
	ConfigKeyOIDCClientSecret          = "oidc_client_secret"
	ConfigKeyOIDCRedirectURI           = "oidc_redirect_uri"
	// ConfigKeyOIDCScopes is a space-separated scope list ("openid profile
	// email"), mirroring the OAuth wire format so admins paste it verbatim.
	ConfigKeyOIDCScopes = "oidc_scopes"
	// ConfigKeyOIDCSubjectField optionally overrides the userinfo claim mapped
	// to the external subject id (default "sub").
	ConfigKeyOIDCSubjectField = "oidc_subject_field"
)

// ErrConnectionTypeUnsupported is returned by an AuthenticatorFactory for a
// connection whose Type it cannot instantiate at runtime (today: TypeSAML —
// the SAML stack is a nested Go module the core cannot import, so a SAML
// connection routes through the SAML module's own endpoints, not this seam).
var ErrConnectionTypeUnsupported = errors.New("connections: connection type unsupported")

// AuthenticatorFactory builds the live upstream authenticator for a resolved
// connection. Implementations are expected to cache built authenticators
// (keyed by connection identity + config version) and MUST be safe for
// concurrent use — the login path calls this per request. A build failure is
// an operator misconfiguration: implementations should surface it to the
// operator (audit/log); callers MUST collapse it to the same wire error as an
// unknown provider (anti-enumeration).
type AuthenticatorFactory interface {
	AuthenticatorFor(ctx context.Context, c *Connection) (core.Authenticator, error)
}
