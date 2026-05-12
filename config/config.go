// Package config loads SSO server configuration from a YAML file and exposes
// helpers that translate it into sso.Option values and per-authenticator
// settings. Code-only inputs (password verifier, SMS sender, CA pool, ...)
// are still wired in Go because they're not safely expressible in YAML.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/permissions"
)

// Default config file name searched if no path is given.
const DefaultFileName = "config.yaml"

// Config is the root configuration document.
type Config struct {
	Server         ServerConfig          `yaml:"server"`
	Authenticators AuthenticatorsConfig  `yaml:"authenticators"`
	Logging        LoggingConfig         `yaml:"logging"`
	Audit          AuditConfig           `yaml:"audit"`
	Permissions    PermissionsConfig     `yaml:"permissions"`
	Clients        []ClientConfig        `yaml:"clients"`
}

// PermissionsConfig configures role/menu authorization. When disabled, the
// /permissions/me, /menus/me, /roles/me endpoints reply 501.
type PermissionsConfig struct {
	Enabled      bool                     `yaml:"enabled"`
	EmbedInLogin bool                     `yaml:"embed_in_login"`
	Apps         []AppPermissionsConfig   `yaml:"apps"`
	UserRoles    []UserRoleAssignment     `yaml:"user_roles"`
}

// AppPermissionsConfig declares the roles and menu tree for one APP. Roles
// listed here are referenced by UserRoleAssignment.Roles for assignment.
type AppPermissionsConfig struct {
	ClientID string               `yaml:"client_id"`
	Roles    []permissions.Role   `yaml:"roles"`
	Menus    permissions.MenuTree `yaml:"menus"`
}

// UserRoleAssignment binds a user to a set of role codes within a given APP.
type UserRoleAssignment struct {
	UserID   string   `yaml:"user_id"`
	ClientID string   `yaml:"client_id"`
	Roles    []string `yaml:"roles"`
}

// BuildPermissionProvider materializes a permissions.MemoryProvider from the
// static config. Returns nil when permissions are disabled.
func (c *Config) BuildPermissionProvider() *permissions.MemoryProvider {
	if !c.Permissions.Enabled {
		return nil
	}
	p := permissions.NewMemoryProvider()
	for _, app := range c.Permissions.Apps {
		for _, role := range app.Roles {
			p.AddRole(app.ClientID, role)
		}
		if app.Menus != nil {
			p.SetMenus(app.ClientID, app.Menus)
		}
	}
	for _, a := range c.Permissions.UserRoles {
		p.AssignRoles(a.UserID, a.ClientID, a.Roles)
	}
	return p
}

// AuditConfig configures security audit logging. When Enabled is false, no
// audit Recorder is wired and the API endpoints are not mounted.
type AuditConfig struct {
	Enabled        bool `yaml:"enabled"`
	APIEnabled     bool `yaml:"api_enabled"`
	MemoryCapacity int  `yaml:"memory_capacity"`
}

// ServerConfig holds top-level Server tunables.
type ServerConfig struct {
	Issuer               string        `yaml:"issuer"`
	BaseURL              string        `yaml:"base_url"`
	Listen               string        `yaml:"listen"`
	SessionTTL           time.Duration `yaml:"session_ttl"`
	TokenTTL             time.Duration `yaml:"token_ttl"`
	DefaultTokenStrategy string        `yaml:"default_token_strategy"`
}

// LoggingConfig controls the embedded logger.
type LoggingConfig struct {
	Level string `yaml:"level"` // debug | info | error
}

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
}

// AuthenticatorsConfig toggles and tunes each available authenticator.
// All sub-sections are nullable — omit a section to disable that method.
type AuthenticatorsConfig struct {
	Password    *PasswordConfig    `yaml:"password,omitempty"`
	Phone       *CodeAuthConfig    `yaml:"phone,omitempty"`
	Email       *CodeAuthConfig    `yaml:"email,omitempty"`
	TempToken   *TempTokenConfig   `yaml:"temp_token,omitempty"`
	KeyPair     *KeyPairConfig     `yaml:"keypair,omitempty"`
	APIKey      *APIKeyConfig      `yaml:"apikey,omitempty"`
	Certificate *CertificateConfig `yaml:"certificate,omitempty"`
}

// PasswordConfig is presently a marker — verifier comes from code.
type PasswordConfig struct {
	Enabled bool `yaml:"enabled"`
}

// CodeAuthConfig configures phone (SMS) and email OTP flows.
type CodeAuthConfig struct {
	Enabled    bool          `yaml:"enabled"`
	CodeLength int           `yaml:"code_length"`
	CodeTTL    time.Duration `yaml:"code_ttl"`
}

// TempTokenConfig configures the temporary-token authenticator.
type TempTokenConfig struct {
	Enabled bool          `yaml:"enabled"`
	TTL     time.Duration `yaml:"ttl"`
}

// KeyPairConfig configures Ed25519 signature verification.
type KeyPairConfig struct {
	Enabled      bool          `yaml:"enabled"`
	MaxClockSkew time.Duration `yaml:"max_clock_skew"`
}

// APIKeyConfig is presently a marker — keys come from a runtime store.
type APIKeyConfig struct {
	Enabled bool `yaml:"enabled"`
}

// CertificateConfig configures X.509 certificate authentication.
type CertificateConfig struct {
	Enabled         bool     `yaml:"enabled"`
	TrustedCAFiles  []string `yaml:"trusted_ca_files"`
	IntermediateFiles []string `yaml:"intermediate_files"`
}

// Load reads and parses a YAML config file, then applies defaults.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultFileName
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Issuer == "" {
		c.Server.Issuer = sso.DefaultIssuer
	}
	if c.Server.SessionTTL == 0 {
		c.Server.SessionTTL = sso.DefaultSessionDuration
	}
	if c.Server.TokenTTL == 0 {
		c.Server.TokenTTL = sso.DefaultTokenTTL
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Authenticators.Phone != nil {
		applyCodeDefaults(c.Authenticators.Phone, authenticators.DefaultPhoneCodeTTL)
	}
	if c.Authenticators.Email != nil {
		applyCodeDefaults(c.Authenticators.Email, authenticators.DefaultEmailCodeTTL)
	}
	if c.Authenticators.TempToken != nil && c.Authenticators.TempToken.TTL == 0 {
		c.Authenticators.TempToken.TTL = authenticators.DefaultTempTokenTTL
	}
	if c.Authenticators.KeyPair != nil && c.Authenticators.KeyPair.MaxClockSkew == 0 {
		c.Authenticators.KeyPair.MaxClockSkew = authenticators.DefaultKeyPairClockSkew
	}
}

func applyCodeDefaults(c *CodeAuthConfig, ttl time.Duration) {
	if c.CodeLength == 0 {
		c.CodeLength = authenticators.DefaultCodeLength
	}
	if c.CodeTTL == 0 {
		c.CodeTTL = ttl
	}
}

func (c *Config) validate() error {
	level := strings.ToLower(c.Logging.Level)
	switch level {
	case "debug", "info", "error":
	default:
		return fmt.Errorf("config: invalid logging.level %q", c.Logging.Level)
	}
	for _, cl := range c.Clients {
		if cl.ID == "" {
			return errors.New("config: client.id required")
		}
	}
	return nil
}

// ServerOptions returns the sso.Option values implied by the configuration.
// Wire dependency-injected providers (TokenIssuer, UserProvider, ...) and
// authenticators separately.
func (c *Config) ServerOptions() []sso.Option {
	opts := []sso.Option{
		sso.WithIssuer(c.Server.Issuer),
		sso.WithBaseURL(c.Server.BaseURL),
		sso.WithSessionTTL(c.Server.SessionTTL),
		sso.WithTokenTTL(c.Server.TokenTTL),
	}
	if c.Server.DefaultTokenStrategy != "" {
		opts = append(opts, sso.WithDefaultTokenStrategy(c.Server.DefaultTokenStrategy))
	}
	return opts
}
