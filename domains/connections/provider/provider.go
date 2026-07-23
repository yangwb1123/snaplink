// Package provider models third-party login providers — the OIDC/SAML upstream
// identity providers a tenant can register so their users authenticate via an
// external IdP (Google, GitHub, Okta, ADFS, etc.) rather than or in addition to
// the built-in password authenticator.
//
// A Provider is a TENANT-SCOPED resource: every provider belongs to exactly one
// tenant (TenantID), and a tenant admin manages their own provider set. The
// special TenantID "" means a GLOBAL provider available to all tenants.
//
// A Client (OAuth app) can whitelist which providers appear on its login page
// via AllowedProviderIDs; empty means "show all enabled providers for this
// tenant".
package provider

import "time"

// ProviderType identifies the protocol the upstream IdP speaks.
type ProviderType string

const (
	// TypeOIDC is an OpenID Connect provider.
	TypeOIDC ProviderType = "oidc"
	// TypeSAML is a SAML 2.0 identity provider.
	TypeSAML ProviderType = "saml"
	// TypeBuiltin is a server-internal authenticator (password, webauthn, totp).
	// Builtin providers are NOT tenant-managed; they exist as a singleton set.
	TypeBuiltin ProviderType = "builtin"
)

// Provider is a third-party login provider registered by a tenant admin.
type Provider struct {
	// ID is a unique identifier for this provider (e.g. "google_oidc").
	ID string `json:"id"`

	// TenantID is the tenant that owns this provider.
	// "" means the provider is GLOBAL (available to all tenants).
	TenantID string `json:"tenant_id,omitempty"`

	// Type identifies the upstream IdP protocol.
	Type ProviderType `json:"type"`

	// DisplayName is the human-readable name ("Sign in with Google").
	DisplayName string `json:"display_name"`

	// IconURL is an optional icon URL shown on the login button.
	IconURL string `json:"icon_url,omitempty"`

	// ButtonLabel overrides the default login button text.
	ButtonLabel string `json:"button_label,omitempty"`

	// ButtonColor is a CSS color hint for the login button.
	ButtonColor string `json:"button_color,omitempty"`

	// Enabled gates the provider; a disabled provider is never returned
	// in login provider lists and never used for authentication.
	Enabled bool `json:"enabled"`

	// Config is opaque protocol-specific settings (e.g. oidc_issuer,
	// oidc_client_id, oidc_client_secret, saml_metadata_url). Kept as a
	// map so this model adds no OIDC/SAML dependency — the authenticator
	// factory interprets the keys.
	Config map[string]string `json:"config,omitempty"`

	// CreatedAt is when the provider was registered.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the provider was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// Clone returns a deep copy of the provider.
func (p *Provider) Clone() *Provider {
	cp := *p
	if p.Config != nil {
		cp.Config = make(map[string]string, len(p.Config))
		for k, v := range p.Config {
			cp.Config[k] = v
		}
	}
	return &cp
}

// IsGlobal reports whether this provider is available to all tenants.
func (p *Provider) IsGlobal() bool { return p.TenantID == "" }
