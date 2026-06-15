package config

import "time"

type ProtectedResourceMetadataConfig struct {
	Enabled               bool     `yaml:"enabled"`
	Resource              string   `yaml:"resource"`
	AuthorizationServers  []string `yaml:"authorization_servers"`
	ResourceName          string   `yaml:"resource_name"`
	ResourceDocumentation string   `yaml:"resource_documentation"`
}

// NativeSSOConfig opts into OpenID Connect Native SSO 1.0 — a device_secret is
// issued alongside the tokens when the device_sso scope is requested, and a
// second native app may exchange an id_token + device_secret for its own tokens
// (RFC 8693). Disabled (empty backend) ⇒ byte-identical to a build without it.
type NativeSSOConfig struct {
	Backend string               `yaml:"backend"` // "" (disabled) | memory | sqlite
	SQLite  IdentitySQLiteConfig `yaml:"sqlite"`
	TTL     time.Duration        `yaml:"ttl"` // device_secret lifetime; 0 = SDK default (15m)
}

// SAMLConfig opts into a SAML 2.0 capability supplied by an operator's
// SEPARATE/forked SAML module (the SAML/XML/DSig dependency stays OUT of
// this module's go.mod — the firm zero-external-dep invariant). The
// operator registers a SAMLHandlerFactory by name from their forked main
// (cmd RegisterSAMLHandlers, mirroring RegisterExternalSigner for KMS) and
// selects it here via Handler; the factory builds the SAML SP/IdP HTTP
// handlers + an optional SP-side authenticator, wired with the issuer's
// signing key borrowed as a stdlib crypto.Signer (the CryptoSigner seam).
//
// Handler == "" (the default) ⇒ NO SAML handler is looked up, NO routes
// mount, NO authenticator registers — byte-identical to a build without
// SAML. All the protocol/XML fields below are plain stdlib-typed strings/
// bools so this config struct (and the whole core module) carries no SAML
// type; the forked module interprets them.
type SAMLConfig struct {
	// Handler selects the registered SAMLHandlerFactory (cmd
	// RegisterSAMLHandlers) to build the SAML surface. Empty disables SAML
	// entirely. cmd fails loud (listing registered handlers) when set to an
	// unregistered name — a wiring mistake, not a runtime-recoverable state.
	Handler string `yaml:"handler"`

	// SPProviders lists the SAML Service Providers (or, for an SP-side
	// deployment, the trusted IdPs) the handler should serve. The forked
	// module owns the semantics; these stdlib-typed fields are the portable
	// subset every SAML deployment needs.
	SPProviders []SAMLSPProviderConfig `yaml:"sp_providers"`
}

// SAMLSPProviderConfig is one SAML peer entry — deliberately built from
// stdlib types only (strings/bool), so it carries NO crewjam/SAML type and
// the core module's go.mod stays SAML-free. The operator's forked SAML
// module maps these onto its own SP/IdP descriptor types at boot.
type SAMLSPProviderConfig struct {
	// Name is the local identifier for this peer (used in URLs / logs /
	// authenticator routing, e.g. ?provider=<name>).
	Name string `yaml:"name"`

	// EntityID is the SAML EntityID (issuer) of this peer.
	EntityID string `yaml:"entity_id"`

	// ACSURL is the Assertion Consumer Service URL the IdP POSTs the
	// assertion back to (SP-side), or the SP's ACS this IdP serves.
	ACSURL string `yaml:"acs_url"`

	// IDPMetadataURL / IDPMetadataXML supply the IdP's metadata: a URL the
	// module fetches at boot, or inline XML. Exactly one is typically set;
	// the forked module validates. Inline XML keeps this config self-
	// contained for air-gapped deployments.
	IDPMetadataURL string `yaml:"idp_metadata_url"`
	IDPMetadataXML string `yaml:"idp_metadata_xml"`

	// NameIDFormat selects the SAML NameID format the peer expects (e.g.
	// urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress). Empty ⇒ the
	// module's default.
	NameIDFormat string `yaml:"name_id_format"`

	// AllowIDPInitiated permits unsolicited (IdP-initiated) SSO for this
	// peer. Off by default — IdP-initiated SSO has no in-flight request to
	// bind the assertion to, so it is the weaker, more replay-prone mode;
	// enable only for peers that require it.
	AllowIDPInitiated bool `yaml:"allow_idp_initiated"`
}

// HostedLoginConfig opts into the built-in login UI served at /login/.
// When Enabled is true the operator's cmd binary must also call
// sso.WithHostedLoginFS (typically via go:embed of the web/login directory)
// so the SPA assets are available. The SPA calls /auth/login over JSON —
// zero protocol changes to the OAuth/OIDC surface.
//
// Disabled (the default) ⇒ /login/ is NOT mounted — byte-identical to a
// build without the hosted UI.
