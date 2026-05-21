// Package config loads SSO server configuration from a YAML file and exposes
// helpers that translate it into sso.Option values and per-authenticator
// settings. Code-only inputs (password verifier, SMS sender, CA pool, ...)
// are still wired in Go because they're not safely expressible in YAML.
package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/cors"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/netpolicy/memory"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ratelimit"
)

// Default config file name searched if no path is given.
const DefaultFileName = "config.yaml"

// Config is the root configuration document.
type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Authenticators AuthenticatorsConfig `yaml:"authenticators"`
	Logging        LoggingConfig        `yaml:"logging"`
	Audit          AuditConfig          `yaml:"audit"`
	Permissions    PermissionsConfig    `yaml:"permissions"`
	Network        NetworkConfig        `yaml:"network"`
	Clients        []ClientConfig       `yaml:"clients"`
	Admin          AdminConfig          `yaml:"admin"`
	Bootstrap      BootstrapConfig      `yaml:"bootstrap"`
	Snapshot       SnapshotConfig       `yaml:"snapshot"`
	Releases       ReleasesConfig       `yaml:"releases"`
	Geo            GeoConfig            `yaml:"geo"`
	Tenant             TenantConfig             `yaml:"tenant"`
	Security           SecurityConfig           `yaml:"security"`
	Metrics            MetricsConfig            `yaml:"metrics"`
	OAuth              OAuthConfig              `yaml:"oauth"`
	BackchannelLogout  BackchannelLogoutConfig  `yaml:"backchannel_logout"`
}

// BackchannelLogoutConfig opts into OIDC Back-Channel Logout 1.0.
// When Enabled, /logout + /end_session POST a signed logout_token to
// each affected RP's backchannel_logout_uri so they can drop the
// matching session. SessionManager is required for session-scoped
// (`sid` claim) emission — cmd wires the memory SessionManager by
// default, so this flag is sufficient.
//
// Backed by:
//   - Ed25519JWTIssuer (reused from access tokens) as LogoutTokenIssuer
//   - HTTPLogoutNotifier with the SDK default 5s timeout
//   - MemorySubjectClientIndex so a logout reaches every other RP the
//     subject has active sessions on (single-replica only; multi-
//     replica needs a shared index)
//
// MaxConcurrent caps the fan-out parallelism per logout (default 8).
type BackchannelLogoutConfig struct {
	Enabled       bool `yaml:"enabled"`
	MaxConcurrent int  `yaml:"max_concurrent"`
}

// OAuthConfig opts into the OAuth/OIDC grant stores that cmd's binary
// wires. Each sub-block independently enables one grant:
//
//   - AuthCode  → grant_type=authorization_code (RFC 6749 §4.1)
//   - Refresh   → grant_type=refresh_token (RFC 6749 §6 — single-use rotation)
//   - Device    → grant_type=urn:ietf:params:oauth:grant-type:device_code (RFC 8628)
//   - PAR       → /par + request_uri (RFC 9126)
//
// Without these flags the corresponding endpoints return 501. Memory
// backends are wired today; SQLite / Redis can be plugged in by
// embedding apps.
//
// Each block's TTL is optional; <=0 falls back to the SDK default
// constants (DefaultAuthCodeTTL, DefaultRefreshTokenTTL, DefaultDeviceCodeTTL,
// DefaultPARTTL).
type OAuthConfig struct {
	AuthCode     OAuthStoreConfig       `yaml:"auth_code"`
	RefreshToken OAuthStoreConfig       `yaml:"refresh_token"`
	DeviceCode   OAuthDeviceCodeConfig  `yaml:"device_code"`
	PAR          OAuthStoreConfig       `yaml:"par"`
}

// OAuthStoreConfig is the shared shape for the simple TTL-only stores.
type OAuthStoreConfig struct {
	Enabled bool          `yaml:"enabled"`
	TTL     time.Duration `yaml:"ttl"`
}

// OAuthDeviceCodeConfig adds device-code-specific tunables on top of
// the shared TTL: poll_interval (minimum allowed poll cadence, slower
// devices get back slow_down) and verification_base_url (what the
// server tells devices to display; empty derives from the request).
type OAuthDeviceCodeConfig struct {
	Enabled             bool          `yaml:"enabled"`
	TTL                 time.Duration `yaml:"ttl"`
	PollInterval        time.Duration `yaml:"poll_interval"`
	VerificationBaseURL string        `yaml:"verification_base_url"`
}

// MetricsConfig toggles Prometheus instrumentation. When Enabled,
// cmd/sso-server constructs a metrics.Metrics with its own Registry,
// wires sso.WithMetrics so request count / latency / login / token /
// risk counters all fire, and exposes /metrics for scraping.
//
// When an audit AsyncSink is also wired (audit.async.enabled), the
// matching metrics.AsyncSinkCollector is registered automatically so
// drop counters and queue depth land on the same registry.
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SecurityConfig groups operator-facing security tunables that hook
// into the Server's middleware stack (body limit + rate limit + CORS).
// Each sub-block is opt-in — leaving the block out (or setting
// Enabled=false) skips the corresponding middleware with zero
// overhead. See AGENTS.md §8d / §8f / §8g for the runtime behavior
// of each.
type SecurityConfig struct {
	BodyLimit BodyLimitConfig `yaml:"body_limit"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	CORS      CORSConfig      `yaml:"cors"`
	DPoPNonce DPoPNonceConfig `yaml:"dpop_nonce"`
	JTIReplay JTIReplayConfig `yaml:"jti_replay"`
}

// JTIReplayConfig opts into RFC 9101 §10.8 + RFC 9449 §11.1 jti-based
// replay protection on JWTs the server consumes (JAR request objects;
// DPoP proofs and JWT bearer client assertions follow the same store).
// Without it, signature-valid JWTs are accepted once per validation —
// the spec-permitted but weaker fallback.
//
// The wired backend is in-memory and single-replica only — a jti
// seen by replica A is unknown to replica B, defeating the defense.
// Multi-replica deployments MUST plug a shared backend (Redis,
// Memcached) via sso.WithJTIReplayStore directly.
type JTIReplayConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DPoPNonceConfig opts into RFC 9449 §8 server-issued nonces. When
// Enabled, every DPoP-bearing request must echo a fresh nonce in
// the proof JWT — the AS/RS challenges with `use_dpop_nonce` and
// delivers a nonce via the `DPoP-Nonce` response header on each
// rejection.
//
// KeyFile points at a file containing the HMAC signing key. Required
// in multi-replica deployments so nonces issued by one replica
// verify on every other; single-replica setups may leave it empty
// to auto-generate a 32-byte process-local secret on boot. The
// file's first 64 hex chars (or first 32 raw bytes) seed the key;
// anything beyond that is ignored.
//
// TTL bounds nonce freshness; <= 0 falls back to the SDK default
// (5 minutes).
type DPoPNonceConfig struct {
	Enabled bool          `yaml:"enabled"`
	KeyFile string        `yaml:"key_file"`
	TTL     time.Duration `yaml:"ttl"`
}

// BodyLimitConfig caps request body size. MaxBytes=0 disables the
// limit (sso.WithBodyLimit is not wired). Typical production value:
// 1048576 (1 MiB) — generous for any auth-flow payload, blocks
// gigabyte-class DoS.
type BodyLimitConfig struct {
	MaxBytes int64 `yaml:"max_bytes"`
}

// RateLimitConfig configures the token-bucket middleware. Default
// values apply to every path not matched by a Prefixes entry; per-
// prefix overrides tighten the bucket for hot endpoints like
// /auth/login.
type RateLimitConfig struct {
	Enabled       bool                    `yaml:"enabled"`
	DefaultPerSec float64                 `yaml:"default_per_sec"`
	DefaultBurst  int                     `yaml:"default_burst"`
	Prefixes      []RateLimitPrefixConfig `yaml:"prefixes"`
}

// RateLimitPrefixConfig is one path-prefix rule inside RateLimitConfig.
// Order matters — first match wins, evaluated in declaration order.
type RateLimitPrefixConfig struct {
	Prefix string  `yaml:"prefix"`
	PerSec float64 `yaml:"per_sec"`
	Burst  int     `yaml:"burst"`
}

// CORSConfig configures the CORS middleware. AllowedOrigins is the
// only required field; leaving it empty disables CORS even when
// Enabled=true (the middleware reduces to identity).
type CORSConfig struct {
	Enabled          bool          `yaml:"enabled"`
	AllowedOrigins   []string      `yaml:"allowed_origins"`
	AllowedMethods   []string      `yaml:"allowed_methods"`
	AllowedHeaders   []string      `yaml:"allowed_headers"`
	ExposedHeaders   []string      `yaml:"exposed_headers"`
	AllowCredentials bool          `yaml:"allow_credentials"`
	MaxAge           time.Duration `yaml:"max_age"`
}

// AdminConfig toggles the admin control plane. When Enabled is true the
// sso-server mounts the four admin gRPC services and the grpc-gateway
// REST proxy under /api/v1/admin/. APIRESTEnabled defaults to true when
// Enabled is true; set false to expose admin gRPC-only.
type AdminConfig struct {
	Enabled        bool `yaml:"enabled"`
	APIRESTEnabled bool `yaml:"api_rest_enabled"`
}

// BootstrapConfig configures the first-run init Runner. StatePath is the
// JSON file the file-backed Tracker writes to (defaults to "bootstrap.json"
// when empty). Set Disabled=true to skip the runner entirely (useful in
// tests or when an external orchestrator owns init).
type BootstrapConfig struct {
	Disabled       bool                `yaml:"disabled"`
	StatePath      string              `yaml:"state_path"`
	AdminUserID    string              `yaml:"admin_user_id"`
	AdminClientID  string              `yaml:"admin_client_id"`
	AdminRoleCode  string              `yaml:"admin_role_code"`
	AdminClientApp string              `yaml:"admin_client_app"`

	// AdminPasswordFile is an optional path where the generated
	// admin password is written (mode 0600) on first boot in
	// ADDITION to the stdout banner. Containerized deployments
	// where stdout is async-shipped to a log sink frequently lose
	// the boot banner; pointing at a tmpfs / secret-volume path
	// guarantees retrievability. The file is written once per
	// generation; if the bootstrap step doesn't re-run (already
	// at high-water), the file is NOT touched.
	AdminPasswordFile string              `yaml:"admin_password_file"`
	Lock              BootstrapLockConfig `yaml:"lock"`
}

// BootstrapLockConfig configures the distributed lock the Runner takes
// before applying steps. Backend selects which implementation:
//
//   - "" or "noop"  → no coordination (single-replica default)
//   - "file"        → flock(2) on Lock.File.Path; single-host multi-process
//   - "etcd"        → etcd lease + Txn; multi-replica HA
//
// Key namespaces the lock; defaults to "/sso/bootstrap/<namespace>".
// TTL bounds how long the lease lives between heartbeats; the Runner
// renews on TTL/3. Blocking switches contention behavior between
// fail-fast (default) and retry-with-Backoff.
type BootstrapLockConfig struct {
	Backend  string         `yaml:"backend"`
	Key      string         `yaml:"key"`
	TTL      time.Duration  `yaml:"ttl"`
	Blocking bool           `yaml:"blocking"`
	Backoff  time.Duration  `yaml:"backoff"`
	File     LockFileConfig `yaml:"file"`
	Etcd     LockEtcdConfig `yaml:"etcd"`
}

// LockFileConfig configures the file (flock) lock backend.
type LockFileConfig struct {
	Dir string `yaml:"dir"` // directory the lock file lives in; "" = cwd
}

// LockEtcdConfig configures the etcd lock backend.
type LockEtcdConfig struct {
	Endpoints   []string      `yaml:"endpoints"`
	DialTimeout time.Duration `yaml:"dial_timeout"`
	Username    string        `yaml:"username"`
	Password    string        `yaml:"password"`
}

// SnapshotConfig configures the snapshot subsystem (Phase D-2). When
// Enabled is false the admin SnapshotService is not mounted and the
// bootstrap restore_from_snapshot step no-ops. Storage selects where
// envelopes live (file/inline); Encryption selects how they're sealed
// (none/passphrase). RestoreFrom is a snapshot URI consumed by the
// bootstrap step on first boot — overridden by --bootstrap-restore-from.
type SnapshotConfig struct {
	Enabled     bool                     `yaml:"enabled"`
	Storage     SnapshotStorageConfig    `yaml:"storage"`
	Encryption  SnapshotEncryptionConfig `yaml:"encryption"`
	RestoreFrom string                   `yaml:"restore_from"`
}

// SnapshotStorageConfig picks where Pipeline persists envelopes. Backend
// is "file" (default) or "inline" (in-memory; useful for tests).
type SnapshotStorageConfig struct {
	Backend string             `yaml:"backend"`
	File    SnapshotFileConfig `yaml:"file"`
}

// SnapshotFileConfig configures the file-backed Storage. Dir defaults to
// "./snapshots" when empty.
type SnapshotFileConfig struct {
	Dir string `yaml:"dir"`
}

// SnapshotEncryptionConfig picks the Sealer. Backend is "none" (default,
// envelopes are plaintext JSON) or "passphrase" (argon2id +
// XChaCha20-Poly1305). For passphrase mode set either Passphrase
// (literal, fine for tests) or PassphraseFile (read from disk on boot).
type SnapshotEncryptionConfig struct {
	Backend        string `yaml:"backend"`
	Passphrase     string `yaml:"passphrase"`
	PassphraseFile string `yaml:"passphrase_file"`
}

// ReleasesConfig configures the admin app version pin / rollback
// subsystem (Phase D-3). When Enabled is false the admin
// ReleaseService is not mounted. Store selects the persistence
// backend; Pinner selects the deploy mechanism. Probe (optional)
// gates auto-rollback on Pin failure; SnapshotIntegration (boolean)
// turns on ConfigSnapshot-aware Rollback when the snapshot subsystem
// is also enabled.
type ReleasesConfig struct {
	Enabled             bool                `yaml:"enabled"`
	Store               ReleaseStoreConfig  `yaml:"store"`
	Pinner              ReleasePinnerConfig `yaml:"pinner"`
	Probe               ReleaseProbeConfig  `yaml:"probe"`
	SnapshotIntegration bool                `yaml:"snapshot_integration"`
}

// ReleaseStoreConfig picks where Releases are persisted. Backend is
// "file" (default; one <id>.json per release + a CURRENT marker) or
// "memory" (lost on restart; for tests/demos).
type ReleaseStoreConfig struct {
	Backend string                 `yaml:"backend"`
	File    ReleaseStoreFileConfig `yaml:"file"`
}

// ReleaseStoreFileConfig configures the file-backed Store. Dir
// defaults to "./releases" when empty.
type ReleaseStoreFileConfig struct {
	Dir string `yaml:"dir"`
}

// ReleasePinnerConfig picks the Pinner. Backend choices:
//   - "noop"   — records the call, no-op (default; tests / dry-runs)
//   - "static" — frontend bundle on-disk symlink swap
//   - "docker" — docker compose pull + up -d in BundleDir
type ReleasePinnerConfig struct {
	Backend string                    `yaml:"backend"`
	Static  ReleasePinnerStaticConfig `yaml:"static"`
	Docker  ReleasePinnerDockerConfig `yaml:"docker"`
}

// ReleasePinnerStaticConfig configures the static Pinner. BundleDir
// is the directory containing per-release subdirs + the "current"
// symlink the Pinner swaps.
type ReleasePinnerStaticConfig struct {
	BundleDir string `yaml:"bundle_dir"`
}

// ReleasePinnerDockerConfig configures the docker compose Pinner.
// BundleDir is the working directory containing the operator's
// compose file (the Pinner runs `docker compose pull && up -d` in
// it after rewriting a managed .env). Cmd lets operators swap to
// podman or a custom binary path; defaults to "docker".
type ReleasePinnerDockerConfig struct {
	BundleDir string `yaml:"bundle_dir"`
	Cmd       string `yaml:"cmd"`
}

// ReleaseProbeConfig configures the post-Pin health probe. When
// Backend is empty no probe runs and forward Pin always succeeds
// even if the new release is unhealthy. Backend "http" GETs URL
// and treats 2xx as healthy. Polls / Backoff control the retry loop
// (defaults: 6 attempts × 5s).
type ReleaseProbeConfig struct {
	Backend string                 `yaml:"backend"` // "" | "http"
	HTTP    ReleaseProbeHTTPConfig `yaml:"http"`
	Polls   int                    `yaml:"polls"`
	Backoff time.Duration          `yaml:"backoff"`
}

// ReleaseProbeHTTPConfig configures the http probe.
type ReleaseProbeHTTPConfig struct {
	URL string `yaml:"url"`
}

// GeoConfig configures the IP → geo enrichment middleware. When
// Enabled is false the SSO server skips installing the middleware
// entirely. Backend selects which geo.Provider implementation
// supplies the lookups.
//
// The static backend is in-process and useful for small operator
// curated tables (private RFC1918 ranges, regional office
// blocks). Real geo coverage typically wants a future maxmind
// backend stacked behind static — see geo/ docs.
type GeoConfig struct {
	Enabled bool            `yaml:"enabled"`
	Backend string          `yaml:"backend"` // "static" (default)
	Static  GeoStaticConfig `yaml:"static"`
	// LookupTimeout caps a single Lookup in the request hot path.
	// Defaults to sso.DefaultGeoLookupTimeout (200ms) when zero.
	LookupTimeout time.Duration `yaml:"lookup_timeout"`
}

// GeoStaticConfig configures the in-process CIDR → GeoInfo table.
// Entries are added in declaration order; longest-prefix match
// wins regardless.
type GeoStaticConfig struct {
	Entries []GeoStaticEntry `yaml:"entries"`
}

// GeoStaticEntry is one CIDR → GeoInfo mapping.
type GeoStaticEntry struct {
	CIDR                string `yaml:"cidr"`
	CountryCode         string `yaml:"country_code"`
	Region              string `yaml:"region"`
	City                string `yaml:"city"`
	TimeZone            string `yaml:"time_zone"`
	RecommendedLanguage string `yaml:"recommended_language"` // BCP-47
}

// TenantConfig configures the multi-tenant + multi-domain
// routing layer. When Enabled is false the SSO server skips
// installing the tenant middleware entirely. Backend selects
// which tenant.Store implementation to use; "memory" is the
// only one wired today (production SaaS will want a SQL backend
// — see tenant/ docs).
//
// Tenants + Domains can be seeded via TenantConfig.Tenants and
// TenantConfig.Domains for embedded deployments. Operators
// running an admin-managed setup can leave both empty and
// populate via the (forthcoming) admin TenantService RPCs.
type TenantConfig struct {
	Enabled          bool                       `yaml:"enabled"`
	Backend          string                     `yaml:"backend"` // "memory" (default)
	LookupTimeout    time.Duration              `yaml:"lookup_timeout"`
	IncludeSuspended bool                       `yaml:"include_suspended"`
	Tenants          []TenantSeedConfig         `yaml:"tenants"`
	Domains          []TenantDomainConfig       `yaml:"domains"`
	SuspensionCheck  TenantSuspensionCheckConfig `yaml:"suspension_check"`
}

// TenantSuspensionCheckConfig opts the server into the active
// post-validation gate: tokens whose owning client.TenantID maps to
// a now-Suspended tenant fail validation. Without this, a
// suspension only blocks NEW issuance — bearers minted before the
// flip keep working until natural expiry.
//
// CacheTTL bounds how long a tenant's status may be cached between
// lookups; <= 0 falls back to the SDK default (30s).
type TenantSuspensionCheckConfig struct {
	Enabled  bool          `yaml:"enabled"`
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// TenantSeedConfig declares a tenant to PutTenant on boot.
type TenantSeedConfig struct {
	ID       string            `yaml:"id"`
	Slug     string            `yaml:"slug"`
	Name     string            `yaml:"name"`
	Status   string            `yaml:"status"` // "active" (default) | "suspended"
	Settings map[string]string `yaml:"settings"`
}

// TenantDomainConfig declares a hostname → tenant mapping.
type TenantDomainConfig struct {
	Hostname        string            `yaml:"hostname"`
	TenantID        string            `yaml:"tenant_id"`
	DefaultClientID string            `yaml:"default_client_id"`
	IsApex          bool              `yaml:"is_apex"`
	Branding        map[string]string `yaml:"branding"`
}

// PermissionsConfig configures role/menu authorization. When disabled, the
// /permissions/me, /menus/me, /roles/me endpoints reply 501.
type PermissionsConfig struct {
	Enabled      bool                   `yaml:"enabled"`
	EmbedInLogin bool                   `yaml:"embed_in_login"`
	Apps         []AppPermissionsConfig `yaml:"apps"`
	UserRoles    []UserRoleAssignment   `yaml:"user_roles"`
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
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	for _, app := range c.Permissions.Apps {
		for _, role := range app.Roles {
			_ = p.AddRole(ctx, app.ClientID, role)
		}
		if app.Menus != nil {
			_ = p.SetMenus(ctx, app.ClientID, app.Menus)
		}
	}
	for _, a := range c.Permissions.UserRoles {
		_ = p.AssignRoles(ctx, a.UserID, a.ClientID, a.Roles)
	}
	return p
}

// AuditConfig configures security audit logging. When Enabled is false, no
// audit Recorder is wired and the API endpoints are not mounted.
type AuditConfig struct {
	Enabled        bool             `yaml:"enabled"`
	APIEnabled     bool             `yaml:"api_enabled"`
	MemoryCapacity int              `yaml:"memory_capacity"`
	Async          AuditAsyncConfig `yaml:"async"`
}

// AuditAsyncConfig wraps the configured audit sink with an
// audit.AsyncSink so Record calls return on a buffered hot path
// instead of waiting for the inner sink. Critical when the sink is
// network-bound (webhook); pointless overhead for MemorySink.
//
// BufferSize and Workers fall back to library defaults when <= 0.
// RecordTimeoutMs caps a single inner Record call so a hung
// downstream doesn't pin a worker indefinitely (0 = no timeout).
type AuditAsyncConfig struct {
	Enabled         bool `yaml:"enabled"`
	BufferSize      int  `yaml:"buffer_size"`
	Workers         int  `yaml:"workers"`
	RecordTimeoutMs int  `yaml:"record_timeout_ms"`
}

// NetworkConfig configures the network-classification control plane.
//
//   - Enabled=true wires a Store and Classifier into the Server.
//   - APIEnabled=true additionally mounts the REST endpoints
//     (/api/v1/netpolicy/...).
//   - Store selects the backend; "memory" (default) is in-process, "etcd"
//     reads from an etcd cluster (see EtcdEndpoints below).
//   - Policies is the seed list applied at startup. Operators can also add /
//     update / delete policies live via the API.
type NetworkConfig struct {
	Enabled       bool                `yaml:"enabled"`
	APIEnabled    bool                `yaml:"api_enabled"`
	Store         string              `yaml:"store"` // "memory" | "etcd"
	EtcdEndpoints []string            `yaml:"etcd_endpoints"`
	EtcdPrefix    string              `yaml:"etcd_prefix"`
	Policies      []NetworkPolicySeed `yaml:"policies"`
}

// NetworkPolicySeed is the YAML projection of netpolicy.Policy with only the
// fields operators are allowed to set declaratively.
type NetworkPolicySeed struct {
	Name                string            `yaml:"name"`
	CIDRs               []string          `yaml:"cidrs"`
	Hostnames           []string          `yaml:"hostnames"`
	Priority            int32             `yaml:"priority"`
	AdvertisedBaseURL   string            `yaml:"advertised_base_url"`
	AdvertisedJWKSURL   string            `yaml:"advertised_jwks_url"`
	AdvertisedLogoutURL string            `yaml:"advertised_logout_url"`
	Metadata            map[string]string `yaml:"metadata"`
}

// BuildNetworkStore returns a netpolicy.Store configured per NetworkConfig
// and seeds it with the declared policies. Returns nil when network is
// disabled. Callers own the returned store's lifetime — Close it at
// shutdown.
func (c *Config) BuildNetworkStore() (netpolicy.Store, error) {
	if !c.Network.Enabled {
		return nil, nil
	}
	var store netpolicy.Store
	switch strings.ToLower(c.Network.Store) {
	case "", "memory":
		store = memory.New()
	case "etcd":
		// Lazy import: only construct when actually asked for, so unit tests
		// that exercise memory mode don't need etcd reachable.
		return nil, errors.New("config: network.store=etcd: construct via cmd/sso-server directly (needs endpoints + dial timeout)")
	default:
		return nil, fmt.Errorf("config: unknown network.store %q", c.Network.Store)
	}
	for _, seed := range c.Network.Policies {
		if _, err := store.Apply(context.Background(), &netpolicy.Policy{
			Name:                seed.Name,
			CIDRs:               seed.CIDRs,
			Hostnames:           seed.Hostnames,
			Priority:            seed.Priority,
			AdvertisedBaseURL:   seed.AdvertisedBaseURL,
			AdvertisedJWKSURL:   seed.AdvertisedJWKSURL,
			AdvertisedLogoutURL: seed.AdvertisedLogoutURL,
			Metadata:            seed.Metadata,
		}); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("config: seed policy %q: %w", seed.Name, err)
		}
	}
	return store, nil
}

// ServerConfig holds top-level Server tunables.
type ServerConfig struct {
	Issuer               string        `yaml:"issuer"`
	BaseURL              string        `yaml:"base_url"`
	Listen               string        `yaml:"listen"`
	SessionTTL           time.Duration `yaml:"session_ttl"`
	TokenTTL             time.Duration `yaml:"token_ttl"`
	DefaultTokenStrategy string        `yaml:"default_token_strategy"`
	// DiscoveryDocCacheTTL caches the marshaled discovery document
	// + its ETag for this long, keyed by base URL. Set to 0 to
	// disable both the cache and the response Cache-Control / ETag
	// headers (useful when an upstream CDN owns caching). Defaults
	// to the SDK constant when unset (5s).
	DiscoveryDocCacheTTL time.Duration `yaml:"discovery_doc_cache_ttl"`

	// SignedMetadata adds an RFC 8414 §2.1 signed_metadata field
	// to /.well-known/openid-configuration. The configured default
	// TokenIssuer must satisfy the MetadataSigner interface (the
	// built-in Ed25519JWTIssuer does); otherwise this flag is a
	// no-op and an info log is emitted at startup.
	SignedMetadata bool `yaml:"signed_metadata"`

	// SupportedACRValues advertises the OIDC `acr_values_supported`
	// claim on the discovery doc. RPs use it to know which Authentication
	// Context Class References they can demand via `acr_values` /
	// `claims.id_token.acr`. Empty list omits the claim entirely.
	SupportedACRValues []string `yaml:"supported_acr_values"`

	// OperatorMetadata surfaces the OIDC Discovery §3 op_policy_uri,
	// op_tos_uri, and service_documentation fields. RPs link them
	// from consent screens / integrator docs. Each field is
	// independently optional — empty values are omitted.
	OperatorMetadata OperatorMetadataConfig `yaml:"operator_metadata"`
}

// OperatorMetadataConfig groups the three Discovery §3 informational
// URIs. All three fields are independently optional; the SDK omits
// each one whose value is empty.
type OperatorMetadataConfig struct {
	PolicyURI            string `yaml:"policy_uri"`
	TosURI               string `yaml:"tos_uri"`
	ServiceDocumentation string `yaml:"service_documentation"`
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
	// TenantID binds this client to one tenant; empty = no tenant
	// affinity (single-tenant deployments + the platform-admin
	// client). When set, login + token endpoints reject requests
	// whose resolved tenant doesn't match this id.
	TenantID string `yaml:"tenant_id"`
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
	Enabled           bool     `yaml:"enabled"`
	TrustedCAFiles    []string `yaml:"trusted_ca_files"`
	IntermediateFiles []string `yaml:"intermediate_files"`
}

// Load reads and parses a YAML config file, then applies defaults.
//
// Implemented as a thin wrapper over the layered Source/Loader chain
// — equivalent to LoadFromSources(NewFileSource(path)). Use
// LoadFromSources directly when you need ENV / flag / etcd overlays.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultFileName
	}
	return LoadFromSources(context.Background(), NewFileSource(path))
}

// LoadFromSources builds a Loader from the given priority chain
// (lowest → highest) and resolves it into a fully-defaulted +
// validated *Config. Returns the first source / parse / validation
// error encountered.
//
// Typical production wiring:
//
//	cfg, err := config.LoadFromSources(ctx,
//	    config.NewFileSource("/etc/sso/config.yaml"),
//	    &config.FileSource{Path: "/etc/sso/local.yaml", Optional: true},
//	    config.NewEnvSource(),
//	)
//
// CLI flags sit on top of this chain via a forthcoming FlagSource.
func LoadFromSources(ctx context.Context, sources ...Source) (*Config, error) {
	return NewLoader(sources...).Load(ctx)
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
	// Server.{BaseURL,SessionTTL,TokenTTL} are NOT wired here — the
	// matching sso.WithX options are deprecated no-ops. The real
	// session / token lifetimes live on the SessionManager and
	// TokenIssuer constructors; cmd/sso-server reads SessionTTL +
	// TokenTTL directly to feed those constructors.
	opts := []sso.Option{
		sso.WithIssuer(c.Server.Issuer),
	}
	if c.Server.DefaultTokenStrategy != "" {
		opts = append(opts, sso.WithDefaultTokenStrategy(c.Server.DefaultTokenStrategy))
	}

	// Security middleware — body limit + rate limit + CORS. Each
	// opt-in via its own block; absent / disabled blocks omit the
	// corresponding sso.WithX call so the middleware is not wired.
	if c.Security.BodyLimit.MaxBytes > 0 {
		opts = append(opts, sso.WithBodyLimit(c.Security.BodyLimit.MaxBytes))
	}
	if c.Security.RateLimit.Enabled {
		opts = append(opts, sso.WithRateLimit(c.Security.RateLimit.toPolicy()))
	}
	if c.Security.CORS.Enabled && len(c.Security.CORS.AllowedOrigins) > 0 {
		opts = append(opts, sso.WithCORS(c.Security.CORS.toPolicy()))
	}
	return opts
}

// toPolicy builds the ratelimit.Policy implied by the YAML block.
// Default rate / burst applies to unmatched paths; Prefixes layer
// per-endpoint overrides.
func (r *RateLimitConfig) toPolicy() ratelimit.Policy {
	policy := ratelimit.Policy{}
	if r.DefaultPerSec > 0 && r.DefaultBurst > 0 {
		policy.Default = ratelimit.NewMemoryLimiter(r.DefaultPerSec, r.DefaultBurst)
	}
	for _, p := range r.Prefixes {
		if p.Prefix == "" || p.PerSec <= 0 || p.Burst <= 0 {
			continue
		}
		policy.Prefixes = append(policy.Prefixes, ratelimit.PrefixRule{
			Prefix:  p.Prefix,
			Limiter: ratelimit.NewMemoryLimiter(p.PerSec, p.Burst),
		})
	}
	return policy
}

// toPolicy builds the cors.Policy implied by the YAML block. Empty
// AllowedMethods / AllowedHeaders fall back to the cors package's
// defaults (GET/POST/PUT/DELETE/OPTIONS, Authorization/Content-Type).
func (c *CORSConfig) toPolicy() cors.Policy {
	return cors.Policy{
		AllowedOrigins:   c.AllowedOrigins,
		AllowedMethods:   c.AllowedMethods,
		AllowedHeaders:   c.AllowedHeaders,
		ExposedHeaders:   c.ExposedHeaders,
		AllowCredentials: c.AllowCredentials,
		MaxAge:           c.MaxAge,
	}
}
