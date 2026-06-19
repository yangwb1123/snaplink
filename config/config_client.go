package config

import "time"

// ClientConfig is a registered relying-party application.
//
// AllowedAuthenticators (whitelist of provider names) and TokenStrategy (which
// registered TokenIssuer to use) drive the per-app dynamic policy: same SDK,
// different login flows + different token formats per APP.
type ClientConfig struct {
	ID                    string   `yaml:"id"`
	Secret                string   `yaml:"secret"`
	Name                  string   `yaml:"name"`
	RedirectURIs          []string `yaml:"redirect_uris"`
	AllowedScopes         []string `yaml:"allowed_scopes"`
	AllowedAuthenticators []string `yaml:"allowed_authenticators"`
	TokenStrategy         string   `yaml:"token_strategy"`
	Active                bool     `yaml:"active"`
	// TenantID binds this client to one tenant; empty = no tenant
	// affinity (single-tenant deployments + the platform-admin
	// client). When set, login + token endpoints reject requests
	// whose resolved tenant doesn't match this id.
	TenantID string `yaml:"tenant_id"`

	// Below fields mirror the SDK Client struct exactly — the cmd's
	// YAML→Client seeding used to drop them silently, leaving SDK
	// features (RFC 8707 resource allowlist, RFC 9101 JAR client
	// JWKS, OIDC pairwise sub, FAPI 2.0 require-JAR/PAR, OIDC FCL +
	// BCL, per-client TTLs) unreachable via YAML. Every field is
	// optional; omit to use server-wide defaults.
	RequirePKCE                      bool          `yaml:"require_pkce,omitempty"`
	AllowedResources                 []string      `yaml:"allowed_resources,omitempty"`
	PostLogoutRedirectURIs           []string      `yaml:"post_logout_redirect_uris,omitempty"`
	AllowedAuthorizationDetailsTypes []string      `yaml:"allowed_authorization_details_types,omitempty"`
	RefreshTokenTTL                  time.Duration `yaml:"refresh_token_ttl,omitempty"`
	AccessTokenTTL                   time.Duration `yaml:"access_token_ttl,omitempty"`
	AllowedPKCEMethods               []string      `yaml:"allowed_pkce_methods,omitempty"`
	RequireSignedRequestObject       bool          `yaml:"require_signed_request_object,omitempty"`
	RequirePAR                       bool          `yaml:"require_par,omitempty"`
	AllowedRequestURIs               []string      `yaml:"allowed_request_uris,omitempty"`
	DeviceCodeTTL                    time.Duration `yaml:"device_code_ttl,omitempty"`
	DeviceCodePollInterval           time.Duration `yaml:"device_code_poll_interval,omitempty"`
	UserinfoSignedResponseAlg        string        `yaml:"userinfo_signed_response_alg,omitempty"`
	BackchannelLogoutURI             string        `yaml:"backchannel_logout_uri,omitempty"`
	SubjectType                      string        `yaml:"subject_type,omitempty"`
	SectorIdentifierURI              string        `yaml:"sector_identifier_uri,omitempty"`
	FrontchannelLogoutURI            string        `yaml:"frontchannel_logout_uri,omitempty"`
	JWKS                             []ClientJWK   `yaml:"jwks,omitempty"`

	// Per-client consent policy (operator-provisioned; never DCR-settable).
	// SkipConsent bypasses the consent gate for trusted first-party clients;
	// ConsentRefreshInterval (>0) forces periodic re-consent even when scopes
	// still match. Both default off (byte-identical to prior behavior).
	SkipConsent            bool          `yaml:"skip_consent,omitempty"`
	ConsentRefreshInterval time.Duration `yaml:"consent_refresh_interval,omitempty"`

	// Attributes is the open per-client extension bag (mirrors
	// sso.Client.Attributes). Carries server-side registered capabilities
	// such as the OpenID Shared Signals / CAEP receiver:
	//   attributes:
	//     caep_receiver_endpoint: https://rp.example.com/ssf/receive
	//     caep_receiver_auth: "Bearer <token>"
	// caep_receiver_endpoint is validated https at boot.
	Attributes map[string]string `yaml:"attributes,omitempty"`
}

// ClientJWK mirrors sso.JWK in YAML-friendly form. Used to register
// the client's verification keys for RFC 9101 JAR / RFC 7521+7523
// private_key_jwt. The set of supported parameters matches sso.JWK
// (Ed25519 via OKP+Crv+X, RSA via N+E).
type ClientJWK struct {
	Kty string `yaml:"kty"` // "RSA" | "EC" | "OKP"
	Kid string `yaml:"kid"`
	Use string `yaml:"use,omitempty"` // "sig" | "enc"
	Alg string `yaml:"alg,omitempty"` // e.g. "RS256", "EdDSA"

	// RSA
	N string `yaml:"n,omitempty"` // base64url big-endian modulus
	E string `yaml:"e,omitempty"` // base64url big-endian exponent

	// OKP (Ed25519)
	Crv string `yaml:"crv,omitempty"` // "Ed25519"
	X   string `yaml:"x,omitempty"`
}
