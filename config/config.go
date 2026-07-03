// Package config loads SSO server configuration from a YAML file and exposes
// helpers that translate it into sso.Option values and per-authenticator
// settings. Code-only inputs (password verifier, SMS sender, CA pool, ...)
// are still wired in Go because they're not safely expressible in YAML.
package config

import (
	"fmt"
	"log/slog"

	"github.com/snaplink/sso/interfaces/sso"
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
	Events             EventsConfig                    `yaml:"events"`
	Permissions        PermissionsConfig               `yaml:"permissions"`
	Network            NetworkConfig                   `yaml:"network"`
	Clients            []ClientConfig                  `yaml:"clients"`
	Admin              AdminConfig                     `yaml:"admin"`
	Bootstrap          BootstrapConfig                 `yaml:"bootstrap"`
	Snapshot           SnapshotConfig                  `yaml:"snapshot"`
	DR                 DRConfig                        `yaml:"dr"`
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
	NativeSSO          NativeSSOConfig                 `yaml:"native_sso"`
	ProtectedResource  ProtectedResourceMetadataConfig `yaml:"protected_resource_metadata"`
	Trust              TrustConfig                     `yaml:"trust"`
	FeatureGates       FeatureGatesConfig              `yaml:"feature_gates"`
	ConfigAudit        ConfigAuditConfig               `yaml:"config_audit"`
	Rotation           RotationConfig                  `yaml:"rotation"`
	BreakGlass         BreakGlassConfig                `yaml:"break_glass"`
}

// FeatureGatesConfig controls which optional protocol surfaces the server
// mounts routes for (attack-surface reduction for deployment shapes that
// only need a subset of the SSO server's protocol coverage). Every field is
// a *bool so the YAML/env loader can distinguish "operator did not mention
// this key" (nil — the surface stays exactly as it was before this config
// section existed) from an explicit `false` (the surface's routes are NOT
// registered at all). See sso.FeatureGates for the full semantics, including
// why a surface's own opt-in config (e.g. caep.receiver) keeps gating its
// routes on top of this rather than being overridden by it.
//
// Declared here (rather than its own config_gates.go) because config/ is at
// its frozen per-directory file-count ceiling (directory_fanout_test.go) —
// this is a root-level `feature_gates:` YAML section exactly like every
// other top-level Config field, so config.go is its natural home.
//
// YAML:
//
//	feature_gates:
//	  oidc: false          # OAuth-2.0-only deployment
//	  admin_api: false     # no admin tooling for this replica
//
// ENV (SSO_ prefix, "__" nesting, matches every other config section):
//
//	SSO_FEATURE_GATES__OIDC=false
type FeatureGatesConfig struct {
	OIDC        *bool `yaml:"oidc"`
	CIBA        *bool `yaml:"ciba"`
	CAEP        *bool `yaml:"caep"`
	Federation  *bool `yaml:"federation"`
	SelfService *bool `yaml:"self_service"`
	AdminAPI    *bool `yaml:"admin_api"`
	WebSPA      *bool `yaml:"web_spa"`
}

// toSSOGates converts the YAML/env-sourced config into the sso.FeatureGates
// value ServerOptions() feeds to sso.WithFeatureGates. A field-by-field copy
// (rather than a type alias) keeps the config package's wire schema and the
// SDK's runtime type free to evolve independently.
func (c FeatureGatesConfig) toSSOGates() sso.FeatureGates {
	return sso.FeatureGates{
		OIDC:        c.OIDC,
		CIBA:        c.CIBA,
		CAEP:        c.CAEP,
		Federation:  c.Federation,
		SelfService: c.SelfService,
		AdminAPI:    c.AdminAPI,
		WebSPA:      c.WebSPA,
	}
}

// anySet reports whether the operator mentioned at least one feature_gates
// key. ServerOptions() only appends sso.WithFeatureGates when this is true —
// an all-nil FeatureGatesConfig is functionally IDENTICAL to never calling
// the option at all (every gate already defaults to on), so skipping the
// call keeps ServerOptions' output byte-identical to a pre-gate build
// (existing tests assert its exact length) rather than merely
// behaviorally equivalent.
func (c FeatureGatesConfig) anySet() bool {
	return c.OIDC != nil || c.CIBA != nil || c.CAEP != nil || c.Federation != nil ||
		c.SelfService != nil || c.AdminAPI != nil || c.WebSPA != nil
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
