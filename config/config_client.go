package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

// ClientConfig is a registered relying-party application.
//
// AllowedAuthenticators (whitelist of provider names) and TokenStrategy (which
// registered TokenIssuer to use) drive the per-app dynamic policy: same SDK,
// different login flows + different token formats per APP.
type ClientConfig struct {
	ID           string   `yaml:"id"`
	Secret       string   `yaml:"secret"`
	Name         string   `yaml:"name"`
	RedirectURIs []string `yaml:"redirect_uris"`
	// RedirectURIPatterns mirrors sso.Client.RedirectURIPatterns (the opt-in
	// snaplink-extension redirect-URI patterns, validated at boot with the
	// shared core grammar; see docs/design/redirect-uri-patterns.md).
	// Empty (default) = exact-match allowlist only, byte-identical.
	RedirectURIPatterns   []string `yaml:"redirect_uri_patterns,omitempty"`
	AllowedScopes         []string `yaml:"allowed_scopes"`
	AllowedAuthenticators []string `yaml:"allowed_authenticators"`
	LoginPageURI          string   `yaml:"login_page_uri,omitempty"`
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
	RequirePKCE bool `yaml:"require_pkce,omitempty"`
	// TokenEndpointAuthMethod selects the RFC 7591 client authentication
	// contract used at the token endpoint. Operator-provisioned browser SPAs
	// must set this to "none" and pair it with PKCE; an empty value preserves
	// the OAuth default client_secret_basic behavior.
	TokenEndpointAuthMethod          string        `yaml:"token_endpoint_auth_method,omitempty"`
	AllowedResources                 []string      `yaml:"allowed_resources,omitempty"`
	PostLogoutRedirectURIs           []string      `yaml:"post_logout_redirect_uris,omitempty"`
	AllowedAuthorizationDetailsTypes []string      `yaml:"allowed_authorization_details_types,omitempty"`
	RefreshTokenTTL                  time.Duration `yaml:"refresh_token_ttl,omitempty"`
	AccessTokenTTL                   time.Duration `yaml:"access_token_ttl,omitempty"`
	AllowedPKCEMethods               []string      `yaml:"allowed_pkce_methods,omitempty"`
	RequireSignedRequestObject       bool          `yaml:"require_signed_request_object,omitempty"`
	RequirePAR                       bool          `yaml:"require_par,omitempty"`
	// AllowPasswordlessOnly mirrors sso.Client.AllowPasswordlessOnly: when
	// true, this client refuses the "password" provider at /auth/login and
	// requires a WebAuthn passkey (provider=webauthn) instead. Every other
	// authenticator stays available. Default false = no-op.
	AllowPasswordlessOnly     bool          `yaml:"allow_passwordless_only,omitempty"`
	AllowedRequestURIs        []string      `yaml:"allowed_request_uris,omitempty"`
	DeviceCodeTTL             time.Duration `yaml:"device_code_ttl,omitempty"`
	DeviceCodePollInterval    time.Duration `yaml:"device_code_poll_interval,omitempty"`
	UserinfoSignedResponseAlg string        `yaml:"userinfo_signed_response_alg,omitempty"`
	// IDTokenSignedResponseAlg mirrors
	// sso.Client.IDTokenSignedResponseAlg (OIDC Core §3.1.3.1 / RFC 7591 §2
	// `id_token_signed_response_alg`): the JWS algorithm the AS signs THIS
	// client's ID Tokens with. Empty = the server's default id_token
	// issuer (unchanged behavior). The value MUST match the wired signing
	// alg (keys.signing.alg) — config validation rejects anything else at
	// boot, matching the DCR rule that a client can only register an alg
	// the AS can actually produce.
	IDTokenSignedResponseAlg string      `yaml:"id_token_signed_response_alg,omitempty"`
	BackchannelLogoutURI     string      `yaml:"backchannel_logout_uri,omitempty"`
	SubjectType              string      `yaml:"subject_type,omitempty"`
	SectorIdentifierURI      string      `yaml:"sector_identifier_uri,omitempty"`
	FrontchannelLogoutURI    string      `yaml:"frontchannel_logout_uri,omitempty"`
	JWKS                     []ClientJWK `yaml:"jwks,omitempty"`

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

func validateClientRedirectPatterns(client *ClientConfig) error {
	for index, pattern := range client.RedirectURIPatterns {
		if err := core.ValidateRedirectURIPattern(pattern); err != nil {
			return fmt.Errorf("config: client %q redirect_uri_patterns[%d]: %w", client.ID, index, err)
		}
	}
	return nil
}

func validateClientTokenEndpointAuthMethod(client *ClientConfig) error {
	switch client.TokenEndpointAuthMethod {
	case "", "client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth", "self_signed_tls", "none":
		return nil
	default:
		return fmt.Errorf("config: client %q token_endpoint_auth_method %q is not supported", client.ID, client.TokenEndpointAuthMethod)
	}
}

func validateConfiguredClients(c *Config) error {
	// The JWS name the server's own signing issuer produces for keys.signing.alg
	// (same mapping serverbuildsign.BuildSigningIssuer uses);
	// clients[].id_token_signed_response_alg may only name THIS alg — the cmd
	// wires exactly one signing issuer, so any other value would be
	// registered-but-never-honored (id_token omitted at issuance).
	wiredAlg := canonicalSigningAlg(c.Keys.Signing.Alg)
	for _, client := range c.Clients {
		if client.ID == "" {
			return errors.New("config: client.id required")
		}
		if err := validateClientRedirectPatterns(&client); err != nil {
			return err
		}
		if err := validateClientTokenEndpointAuthMethod(&client); err != nil {
			return err
		}
		if client.LoginPageURI != "" && !sso.IsFederatedLoginPageURIValid(client.LoginPageURI) {
			return fmt.Errorf("config: client %q login_page_uri must be HTTPS or loopback HTTP", client.ID)
		}
		if client.IDTokenSignedResponseAlg != "" && client.IDTokenSignedResponseAlg != wiredAlg {
			return fmt.Errorf("config: client %q id_token_signed_response_alg %q is not the wired signing alg %q",
				client.ID, client.IDTokenSignedResponseAlg, wiredAlg)
		}
		if client.TokenEndpointAuthMethod == "none" {
			if client.Secret != "" {
				return fmt.Errorf("config: public client %q must not configure a secret", client.ID)
			}
			if !client.RequirePKCE {
				return fmt.Errorf("config: public client %q must require PKCE", client.ID)
			}
		}
	}
	return nil
}

// ClientSecretRotationConfig opts into scheduled OAuth client-secret rotation
// via the same unified credential-rotation framework the webhook-HMAC secret
// uses (RotationConfig / platform/lifecycle/rotation): a background sweep
// periodically calls the EXISTING admin-triggered core.ClientStore.RotateSecret
// for every client whose secret has aged past Interval, instead of relying on
// an operator's own cron hitting the admin RotateSecret RPC. Disabled by
// default: a zero-value section wires nothing, byte-identical to a build
// without the feature.
//
// The YAML key is client_secret_rotation (NOT nested under the existing
// `clients:` key) because `clients:` already names the seed-client LIST
// ([]ClientConfig) — reusing it as an object with a nested secret_rotation
// key would collide with that array.
//
// Shape deliberately mirrors RotationConfig's Enabled/Interval/Overlap for
// operator-facing consistency between the two rotation features.
// Tick/RetryBase/RetryMax are NOT duplicated here: both rotators register
// onto ONE shared rotation.Scheduler (cmd wires them together), so the
// polling tick + failure-retry backoff is configured ONCE under `rotation:`
// — only the per-rotator knobs (whether it runs, how often, how much
// overlap) belong to each rotator's own section.
//
// Requires a ClientStore that implements
// shared/security/clientrotation.ClientRotationLister (the memory + sqlite
// defaultimpl backends do); cmd fails loud at boot otherwise rather than
// silently never rotating anything.
//
// Lives here (rather than beside RotationConfig in config_snapshot.go)
// because config/ is at its frozen per-directory file-count ceiling
// (directory_fanout_test.go) and config_snapshot.go itself has almost no
// line budget left — this file (the client seed/config schema) is the
// closest topical fit with room to spare.
type ClientSecretRotationConfig struct {
	Enabled bool `yaml:"enabled"`

	// Interval is BOTH the sweep cadence and the per-client staleness bar: a
	// client is due once its secret is >= Interval old. Required (> 0) when
	// Enabled.
	Interval time.Duration `yaml:"interval"`

	// Overlap keeps the previous hash valid while an application deploys the
	// newly-issued secret. Zero selects the secure 24-hour default; explicit
	// values must be at least one hour.
	Overlap time.Duration `yaml:"overlap"`

	// Lifetime is the validity period installed on each newly rotated secret.
	// Zero selects Interval+Overlap so a scheduled rotation has a full grace
	// window before the credential can expire.
	Lifetime time.Duration `yaml:"lifetime"`
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
