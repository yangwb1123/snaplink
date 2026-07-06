package config

import "time"

type HostedLoginConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SelfServiceConfig wires the end-user self-service stores the hosted login +
// portal SPAs depend on. Each store is opt-in: an empty backend leaves its
// routes unmounted and behavior byte-identical to a build without it. The
// MFA-factor management store (/me/mfa) is intentionally not here — it is
// operator-implemented over the concrete TOTP/WebAuthn backends, not a generic
// memory|sqlite toggle. Self-service password change (/me/password) likewise
// needs the operator's user-provisioning model and is wired by the embedder.
type SelfServiceConfig struct {
	// Consent backs the consent gate + records (/consents/me, consent_required)
	// plus the optional server-wide consent grant TTL ceiling. Enabling it
	// (Backend set) turns ON consent enforcement at /auth/login.
	Consent ConsentConfig `yaml:"consent"`
	// Password backs self-service password change (/me/password). When enabled,
	// the YAML-seeded password users are imported into the store (by bcrypt
	// hash) and login is served from it, so a password changed via /me/password
	// takes effect on the next login.
	Password SelfServiceStoreConfig `yaml:"password"`
	// Signup enables the opt-in unauthenticated self-service registration
	// endpoint POST /auth/register (creates a user + sets a password). DEFAULT
	// OFF — open signup is an abuse surface most enterprise deployments don't
	// want; they provision via SCIM/admin. Needs the password store enabled too.
	Signup bool `yaml:"signup"`
	// DataExport mounts GET /me/data-export — the GDPR Art. 15 self-service
	// export of the authenticated user's OWN data (assembled by the same
	// compliance.Exporter the admin route uses, scoped to the caller). Opt-in
	// because it surfaces a user's full data bundle to that user.
	DataExport bool `yaml:"data_export"`
	// AccountDeletion mounts POST /me/account/erase — the GDPR Art. 17
	// self-service erasure of the authenticated user's OWN account (sessions +
	// refresh tokens + user record). Opt-in + IRREVERSIBLE: leave it off for
	// org-managed accounts where only an admin should delete a user.
	AccountDeletion bool `yaml:"account_deletion"`
	// PasswordReset backs the UNAUTHENTICATED forgot-password flow
	// (/auth/forgot-password + /auth/reset-password). Enabling it (backend set)
	// wires the single-use reset-token store + a default identifier resolver
	// (treats the identifier as the userID) + a delivery resolver (UserProvider
	// email). The token DELIVERY mechanism (PasswordResetSender) needs operator
	// email/SMS infra and is wired via the SDK — without it the endpoint stays
	// anti-enumeration-safe but delivers nothing (a startup warning is logged).
	PasswordReset PasswordResetConfig `yaml:"password_reset"`
}

// PasswordResetConfig wires the forgot-password reset-token store. Mirrors
// NativeSSOConfig (Backend + SQLite + TTL). Empty backend = flow disabled.
type PasswordResetConfig struct {
	Backend string               `yaml:"backend"` // "" (disabled) | memory | sqlite
	SQLite  IdentitySQLiteConfig `yaml:"sqlite"`
	TTL     time.Duration        `yaml:"ttl"` // reset-token lifetime; 0 = SDK default (15m)
}

// SelfServiceStoreConfig selects a self-service store backend. Empty Backend =
// disabled (routes unmounted). memory = dev/single-node; sqlite = durable.
type SelfServiceStoreConfig struct {
	Backend string               `yaml:"backend"` // "" | memory | sqlite
	SQLite  IdentitySQLiteConfig `yaml:"sqlite"`
}

// SMTPConfig wires the built-in outbound email sender
// (infrastructure/defaultimpl/emailsmtp) that delivers password-reset,
// email-verification, email-change, org-invitation, and email-OTP messages
// over net/smtp. Enabled=false or an empty Host leaves cmd's four SDK sender
// options unwired — same no-op-delivery behavior as before this existed
// (byte-identical).
type SMTPConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	// Password supports secret:// resolution (config/secrets.go) and the
	// SSO_SMTP__PASSWORD env override — never commit a plaintext password.
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	// StartTLS documents intent (net/smtp.SendMail negotiates STARTTLS
	// automatically whenever the server advertises it, and falls back to
	// plaintext otherwise, so there is no separate code branch to gate).
	// Implicit TLS (port 465) is a deferred follow-up.
	StartTLS bool `yaml:"starttls"`
	// Timeout bounds each background send; 0 = SDK default (10s).
	Timeout time.Duration `yaml:"timeout"`
	// TemplatesDir overlays the five go:embed default templates
	// (password_reset/email_verification/email_change/invitation/otp) from
	// disk when set; empty = embedded defaults only.
	TemplatesDir string `yaml:"templates_dir"`
	// LinkBaseURL is prefixed to reset/verify/invite links; required because
	// the sender only sees the token/target from its SPI signature, never
	// server.issuer.
	LinkBaseURL string `yaml:"link_base_url"`
}

// ConsentConfig extends SelfServiceStoreConfig with the optional
// server-wide consent grant TTL ceiling. Mirrors NativeSSOConfig's shape
// (Backend + SQLite + TTL). MaxTTL wires interfaces/sso.WithConsentTTL: a
// HARD ceiling on every recorded consent grant's lifetime, after which
// GetConsent treats the grant as absent and /auth/login re-prompts. It is
// independent of, and can only be tightened (never loosened) by, a
// client's own ConsentRefreshInterval. 0 (the default) means no
// server-enforced expiry — byte-identical to a build without this field
// set.
type ConsentConfig struct {
	SelfServiceStoreConfig `yaml:",inline"`
	MaxTTL                 time.Duration `yaml:"max_ttl"`
}

// MeshConfig opts into the service-mesh data-plane integrations
// (cluster C1). Today it carries the ext_authz HTTP-mode authorization
// endpoint (the gRPC ext_authz variant needs the go-control-plane proto
// dep and lives in a separate operator module).
