// Package config loads SSO server configuration from a YAML file and exposes
// helpers that translate it into sso.Option values and per-authenticator
// settings. Code-only inputs (password verifier, SMS sender, CA pool, ...)
// are still wired in Go because they're not safely expressible in YAML.
package config

import (
	"fmt"
	"log/slog"
)

// Default config file name searched if no path is given.
const DefaultFileName = "config.yaml"

// Config is the root configuration document.
type Config struct {
	// Version is the configuration schema version. Must match
	// CurrentSchemaVersion. When absent (0 or empty) the server
	// prints a warning and loads the config with best-effort
	// compatibility. Set to CurrentSchemaVersion to silence the
	// warning and opt into forward-compat validation.
	Version int `yaml:"version,omitempty"`

	Server             ServerConfig                    `yaml:"server"`
	Authenticators     AuthenticatorsConfig            `yaml:"authenticators"`
	Logging            LoggingConfig                   `yaml:"logging"`
	Audit              AuditConfig                     `yaml:"audit"`
	Permissions        PermissionsConfig               `yaml:"permissions"`
	Network            NetworkConfig                   `yaml:"network"`
	Clients            []ClientConfig                  `yaml:"clients"`
	Admin              AdminConfig                     `yaml:"admin"`
	Bootstrap          BootstrapConfig                 `yaml:"bootstrap"`
	Snapshot           SnapshotConfig                  `yaml:"snapshot"`
	Releases           ReleasesConfig                  `yaml:"releases"`
	Backup             BackupConfig                    `yaml:"backup"`
	Geo                GeoConfig                       `yaml:"geo"`
	Region             RegionConfig                    `yaml:"region"`
	Tenant             TenantConfig                    `yaml:"tenant"`
	Connections        ConnectionsConfig               `yaml:"connections"`
	Security           SecurityConfig                  `yaml:"security"`
	Metrics            MetricsConfig                   `yaml:"metrics"`
	OAuth              OAuthConfig                     `yaml:"oauth"`
	BackchannelLogout  BackchannelLogoutConfig         `yaml:"backchannel_logout"`
	ClientRegistration ClientRegistrationConfig        `yaml:"client_registration"`
	Identity           IdentityConfig                  `yaml:"identity"`
	WebAuthn           WebAuthnConfig                  `yaml:"webauthn"`
	Registry           RegistryConfig                  `yaml:"registry"`
	Risk               RiskConfig                      `yaml:"risk"`
	MFA                MFAConfig                       `yaml:"mfa"`
	Anomaly            AnomalyConfig                   `yaml:"anomaly"`
	Cluster            ClusterConfig                   `yaml:"cluster"`
	Redis              RedisConfig                     `yaml:"redis"`
	Postgres           PostgresConfig                  `yaml:"postgres"`
	Keys               KeysConfig                      `yaml:"keys"`
	CIBA               CIBAConfig                      `yaml:"ciba"`
	OIDC               OIDCConfig                      `yaml:"oidc"`
	SCIM               SCIMConfig                      `yaml:"scim"`
	DPoP               DPoPConfig                      `yaml:"dpop"`
	CAEP               CAEPConfig                      `yaml:"caep"`
	SPIFFE             SPIFFEConfig                    `yaml:"spiffe"`
	Mesh               MeshConfig                      `yaml:"mesh"`
	Federation         FederationConfig                `yaml:"federation"`
	SAML               SAMLConfig                      `yaml:"saml"`
	HostedLogin        HostedLoginConfig               `yaml:"hosted_login"`
	SelfService        SelfServiceConfig               `yaml:"self_service"`
	SMTP               SMTPConfig                      `yaml:"smtp"`
	NativeSSO          NativeSSOConfig                 `yaml:"native_sso"`
	ProtectedResource  ProtectedResourceMetadataConfig `yaml:"protected_resource_metadata"`
}

// CurrentSchemaVersion is the expected version value for the current
// Config structure. Increment when making a backward-incompatible
// change to the YAML schema (renaming, removing, or changing the
// semantics of a field). Backward-compatible additions (new optional
// fields) do NOT require a version bump.
const CurrentSchemaVersion = 1

// ValidateVersion checks that cfg.Version matches CurrentSchemaVersion.
// When cfg.Version is 0 (unset) it prints a warning suggesting the user
// set it explicitly. Returns an error only when the version is set but
// does not match (mismatch → the config may be for a different server
// version).
func ValidateVersion(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	switch {
	case cfg.Version == 0:
		slog.Warn("config: version field is unset; add 'version: 1' to your config.yaml " +
			"to opt into schema validation and suppress this warning")
	case cfg.Version != CurrentSchemaVersion:
		return fmt.Errorf("config: schema version %d does not match expected version %d; "+
			"your config.yaml may be for a different server release", cfg.Version, CurrentSchemaVersion)
	}
	return nil
}
