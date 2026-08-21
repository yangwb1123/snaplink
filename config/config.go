// Package config loads SSO server configuration from a YAML file and exposes
// helpers that translate it into sso.Option values and per-authenticator
// settings. Code-only inputs (password verifier, SMS sender, CA pool, ...)
// are still wired in Go because they're not safely expressible in YAML.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
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

	Server               ServerConfig                    `yaml:"server"`
	Authenticators       AuthenticatorsConfig            `yaml:"authenticators"`
	Logging              LoggingConfig                   `yaml:"logging"`
	Audit                AuditConfig                     `yaml:"audit"`
	Events               EventsConfig                    `yaml:"events"`
	Permissions          PermissionsConfig               `yaml:"permissions"`
	ReBAC                ReBACConfig                     `yaml:"rebac"`
	Network              NetworkConfig                   `yaml:"network"`
	Clients              []ClientConfig                  `yaml:"clients"`
	ClientSecretRotation ClientSecretRotationConfig      `yaml:"client_secret_rotation"`
	Admin                AdminConfig                     `yaml:"admin"`
	AdminWriteQuota      AdminWriteQuotaConfig           `yaml:"admin_write_quota"`
	AdminChangeApproval  AdminChangeApprovalConfig       `yaml:"admin_change_approval"`
	AdminDestructive     AdminDestructiveActionsConfig   `yaml:"admin_destructive_actions"`
	AdminIPAllowlist     AdminIPAllowlistConfig          `yaml:"admin_ip_allowlist"`
	Bootstrap            BootstrapConfig                 `yaml:"bootstrap"`
	Snapshot             SnapshotConfig                  `yaml:"snapshot"`
	DR                   DRConfig                        `yaml:"dr"`
	Releases             ReleasesConfig                  `yaml:"releases"`
	Backup               BackupConfig                    `yaml:"backup"`
	Geo                  GeoConfig                       `yaml:"geo"`
	Region               RegionConfig                    `yaml:"region"`
	Tenant               TenantConfig                    `yaml:"tenant"`
	Connections          ConnectionsConfig               `yaml:"connections"`
	Security             SecurityConfig                  `yaml:"security"`
	Metrics              MetricsConfig                   `yaml:"metrics"`
	OAuth                OAuthConfig                     `yaml:"oauth"`
	BackchannelLogout    BackchannelLogoutConfig         `yaml:"backchannel_logout"`
	ClientRegistration   ClientRegistrationConfig        `yaml:"client_registration"`
	Identity             IdentityConfig                  `yaml:"identity"`
	WebAuthn             WebAuthnConfig                  `yaml:"webauthn"`
	Registry             RegistryConfig                  `yaml:"registry"`
	Risk                 RiskConfig                      `yaml:"risk"`
	MFA                  MFAConfig                       `yaml:"mfa"`
	Anomaly              AnomalyConfig                   `yaml:"anomaly"`
	Cluster              ClusterConfig                   `yaml:"cluster"`
	Redis                RedisConfig                     `yaml:"redis"`
	Postgres             PostgresConfig                  `yaml:"postgres"`
	Keys                 KeysConfig                      `yaml:"keys"`
	CIBA                 CIBAConfig                      `yaml:"ciba"`
	OIDC                 OIDCConfig                      `yaml:"oidc"`
	SCIM                 SCIMConfig                      `yaml:"scim"`
	DPoP                 DPoPConfig                      `yaml:"dpop"`
	CAEP                 CAEPConfig                      `yaml:"caep"`
	SPIFFE               SPIFFEConfig                    `yaml:"spiffe"`
	TxnToken             TxnTokenConfig                  `yaml:"txn_token"`
	Mesh                 MeshConfig                      `yaml:"mesh"`
	Federation           FederationConfig                `yaml:"federation"`
	SAML                 SAMLConfig                      `yaml:"saml"`
	HostedLogin          HostedLoginConfig               `yaml:"hosted_login"`
	SetupWizard          SetupWizardConfig               `yaml:"setup_wizard"`
	SelfService          SelfServiceConfig               `yaml:"self_service"`
	NativeSSO            NativeSSOConfig                 `yaml:"native_sso"`
	ProtectedResource    ProtectedResourceMetadataConfig `yaml:"protected_resource_metadata"`
	Trust                TrustConfig                     `yaml:"trust"`
	FeatureGates         FeatureGatesConfig              `yaml:"feature_gates"`
	ConfigAudit          ConfigAuditConfig               `yaml:"config_audit"`
	Rotation             RotationConfig                  `yaml:"rotation"`
	BreakGlass           BreakGlassConfig                `yaml:"break_glass"`
	UserLifecycle        UserLifecycleConfig             `yaml:"user_lifecycle"`
	TokenPolicies        TokenPolicyConfig               `yaml:"token_policies"`
	AccessPolicies       AccessPolicyConfig              `yaml:"access_policies"`
	Degradation          DegradationConfig               `yaml:"degradation"`
	SessionTrustDecay    SessionTrustDecayConfig         `yaml:"session_trust_decay"`
	TokenAnomaly         TokenAnomalyConfig              `yaml:"token_anomaly"`
	ThreatAction         ThreatActionConfig              `yaml:"threat_action"`
	Webhooks             WebhooksConfig                  `yaml:"webhooks"`
	SMTP                 SMTPConfig                      `yaml:"smtp"`
	AuthPipeline         AuthPipelineConfig              `yaml:"auth_pipeline"`
	Notifications        NotificationsConfig             `yaml:"notifications"`
}

// ExternalAuditWorkerConfig enables the stock server's one supported
// out-of-process worker capability: redacted audit-batch delivery. Local
// workers require a signed provenance manifest; remote workers require mTLS
// and may additionally pin a SPIFFE URI. AuthToken supports secret:// values.
type ExternalAuditWorkerConfig struct {
	Enabled             bool                         `yaml:"enabled"`
	ModuleID            string                       `yaml:"module_id"`
	Executable          string                       `yaml:"executable"`
	Args                []string                     `yaml:"args"`
	SocketPath          string                       `yaml:"socket_path"`
	AuthToken           string                       `yaml:"auth_token"`
	ExpectedSHA256      string                       `yaml:"expected_sha256"`
	SignaturePath       string                       `yaml:"signature_path"`
	SignaturePublicKey  string                       `yaml:"signature_public_key"`
	ProvenancePath      string                       `yaml:"provenance_path"`
	ProvenancePublicKey string                       `yaml:"provenance_public_key"`
	ReleaseID           string                       `yaml:"release_id"`
	BuildProfile        string                       `yaml:"build_profile"`
	RemoteAddress       string                       `yaml:"remote_address"`
	TLS                 ExternalAuditWorkerTLSConfig `yaml:"tls"`
	PeerSPIFFEID        string                       `yaml:"peer_spiffe_id"`
	StartupTimeout      time.Duration                `yaml:"startup_timeout"`
	RequestTimeout      time.Duration                `yaml:"request_timeout"`
	MaxFrameBytes       int                          `yaml:"max_frame_bytes"`
	MaxBatchEvents      int                          `yaml:"max_batch_events"`
}

// ExternalAuditWorkerTLSConfig holds file-backed client mTLS material. The
// private key is never represented as YAML text; CAFile may be empty to use
// the platform roots, while CertFile and KeyFile are always required for a
// remote worker.
type ExternalAuditWorkerTLSConfig struct {
	CAFile     string `yaml:"ca_file"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ServerName string `yaml:"server_name"`
}

func (c ExternalAuditWorkerConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.ModuleID) == "" || strings.TrimSpace(c.AuthToken) == "" {
		return errors.New("config: audit.external_worker.module_id and auth_token are required")
	}
	if strings.TrimSpace(c.RemoteAddress) != "" {
		return c.validateRemoteWorker()
	}
	return c.validateLocalWorker()
}

func (c ExternalAuditWorkerConfig) validateLocalWorker() error {
	if strings.TrimSpace(c.Executable) == "" || !filepath.IsAbs(c.Executable) || !filepath.IsAbs(c.SocketPath) {
		return errors.New("config: audit.external_worker local mode requires absolute executable and socket_path")
	}
	if strings.TrimSpace(c.ExpectedSHA256) == "" || !filepath.IsAbs(c.ProvenancePath) || strings.TrimSpace(c.ProvenancePublicKey) == "" {
		return errors.New("config: audit.external_worker local mode requires expected_sha256, absolute provenance_path and provenance_public_key")
	}
	if strings.TrimSpace(c.ReleaseID) == "" || strings.TrimSpace(c.BuildProfile) == "" {
		return errors.New("config: audit.external_worker local mode requires release_id and build_profile")
	}
	if (c.SignaturePath == "") != (strings.TrimSpace(c.SignaturePublicKey) == "") {
		return errors.New("config: audit.external_worker signature_path and signature_public_key must be configured together")
	}
	if c.SignaturePath != "" && !filepath.IsAbs(c.SignaturePath) {
		return errors.New("config: audit.external_worker signature_path must be absolute")
	}
	return nil
}

func (c ExternalAuditWorkerConfig) validateRemoteWorker() error {
	if c.Executable != "" || len(c.Args) != 0 || c.SocketPath != "" || c.ExpectedSHA256 != "" || c.ProvenancePath != "" || c.SignaturePath != "" {
		return errors.New("config: audit.external_worker remote mode cannot include local artifact fields")
	}
	if c.SignaturePublicKey != "" || c.ProvenancePublicKey != "" || c.ReleaseID != "" || c.BuildProfile != "" {
		return errors.New("config: audit.external_worker remote mode cannot include local provenance fields")
	}
	if strings.TrimSpace(c.TLS.CertFile) == "" || strings.TrimSpace(c.TLS.KeyFile) == "" {
		return errors.New("config: audit.external_worker remote mode requires tls.cert_file and tls.key_file")
	}
	return nil
}

// AuthPipelineConfig wires the safe built-in lifecycle hooks. Custom and WASM
// hooks remain code-injected because executable policy is not YAML data.
type AuthPipelineConfig struct {
	IPSkipMFACIDRs            []string `yaml:"ip_skip_mfa_cidrs"`
	RequiredProfileAttributes []string `yaml:"required_profile_attributes"`
}

// NotificationsConfig enables the end-user security inbox and audit router.
type NotificationsConfig struct {
	Enabled              bool                     `yaml:"enabled"`
	Backend              string                   `yaml:"backend"`
	SQLite               NotificationSQLiteConfig `yaml:"sqlite"`
	EmailEnabled         bool                     `yaml:"email_enabled"`
	Cooldown             time.Duration            `yaml:"cooldown"`
	QueueSize            int                      `yaml:"queue_size"`
	Workers              int                      `yaml:"workers"`
	SessionExpiryWarning time.Duration            `yaml:"session_expiry_warning"`
	SessionScanInterval  time.Duration            `yaml:"session_scan_interval"`
}

type NotificationSQLiteConfig struct {
	DSN string `yaml:"dsn"`
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
	// Branding is the canonical name of the gate that controls the public
	// per-host branding lookup (GET /branding). It was historically called
	// web_spa; WebSPA below remains accepted as a deprecated alias.
	Branding *bool `yaml:"branding"`
	// WebSPA is the deprecated YAML alias of Branding. Setting both keys is
	// a startup error; setting only web_spa logs a deprecation warning and
	// behaves exactly as branding.
	WebSPA *bool `yaml:"web_spa"`
}

// normalizeFeatureGates resolves the branding/web_spa alias pair: web_spa
// (deprecated) is folded into branding so the rest of the system reads one
// canonical field. Both set → error (ambiguous); only web_spa → deprecation
// warning. Called from validate so an invalid combination fails loud at
// boot.
func (c *Config) normalizeFeatureGates() error {
	fg := &c.FeatureGates
	if fg.Branding != nil && fg.WebSPA != nil {
		return errors.New("config: feature_gates.branding and feature_gates.web_spa are aliases; set only one (web_spa is deprecated)")
	}
	if fg.WebSPA != nil {
		slog.Warn("config: feature_gates.web_spa is deprecated; use feature_gates.branding " +
			"(the gate controls only the public GET /branding lookup)")
		fg.Branding = fg.WebSPA
		fg.WebSPA = nil
	}
	return nil
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
		Branding:    c.Branding,
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
		c.SelfService != nil || c.AdminAPI != nil || c.Branding != nil || c.WebSPA != nil
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
