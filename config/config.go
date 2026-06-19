// Package config loads SSO server configuration from a YAML file and exposes
// helpers that translate it into sso.Option values and per-authenticator
// settings. Code-only inputs (password verifier, SMS sender, CA pool, ...)
// are still wired in Go because they're not safely expressible in YAML.
package config

// Default config file name searched if no path is given.
const DefaultFileName = "config.yaml"

// Config is the root configuration document.
type Config struct {
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
}
