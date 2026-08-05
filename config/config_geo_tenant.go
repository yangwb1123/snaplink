package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/domains/tenant/quotabinding"
	"github.com/yangwb1123/snaplink/shared/core"
)

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

// RegionConfig configures the serving-region resolution middleware + the
// data-residency enforcement gate. It mirrors GeoConfig's discipline: when
// neither ServingRegion nor HeaderName is set the middleware is NOT installed
// and the residency check stays inert — byte-identical to a pre-region build.
//
// ServingRegion is this deployment's pinned region (e.g. "eu-west-1"): the
// ConfigPinnedResolver fallback used when no trusted header supplies one.
// HeaderName is the request header a regional edge/mesh sets to pin traffic
// (empty → DefaultServingRegionHeader, "X-Serving-Region") — ONLY trust it
// behind an edge that strips any client-supplied copy (the X-Forwarded-* /
// X-Auth-* threat model). AllowedRegions is the anti-injection allowlist for
// the header resolver (a header value outside it falls back to ServingRegion).
// ResidencyCheckCacheTTL bounds how long a tenant's ResidencyPolicy is cached
// (<= 0 → the SDK default, DefaultTenantResidencyCacheTTL).
type RegionConfig struct {
	ServingRegion          string                  `yaml:"serving_region"`
	HeaderName             string                  `yaml:"header_name"`
	AllowedRegions         []string                `yaml:"allowed_regions"`
	ResidencyCheckCacheTTL time.Duration           `yaml:"residency_check_cache_ttl"`
	PolicyStore            RegionPolicyStoreConfig `yaml:"policy_store"`
}

// RegionPolicyStoreConfig selects the durable residency-policy source
// (region.PolicyStore). Empty backend = not wired (tenant-row-only
// derivation, byte-identical). memory is in-process; sqlite is
// cluster-shared. Seed entries are operator-declared policies applied at
// boot — an invalid seed region ID fails boot loud.
type RegionPolicyStoreConfig struct {
	Backend string                        `yaml:"backend"` // "" | memory | sqlite
	SQLite  RegionPolicyStoreSQLiteConfig `yaml:"sqlite"`
	Seed    []RegionPolicySeedConfig      `yaml:"seed"`
}

// RegionPolicyStoreSQLiteConfig configures the sqlite policy backend.
type RegionPolicyStoreSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// RegionPolicySeedConfig declares one tenant's residency policy at boot.
type RegionPolicySeedConfig struct {
	TenantID       string   `yaml:"tenant_id"`
	HomeRegion     string   `yaml:"home_region"`
	AllowedRegions []string `yaml:"allowed_regions"`
	EnforceWrites  bool     `yaml:"enforce_writes"`
}

// TenantConfig configures the multi-tenant + multi-domain
// routing layer. When Enabled is false the SSO server skips
// installing the tenant middleware entirely. Backend selects
// which tenant.Store implementation to use — "memory" for
// single-replica dev / tests, "sqlite" for cluster-shared state
// (admin SetTenantStatus on replica A surfaces on every replica
// after the suspension-check cache TTL elapses).
//
// Tenants + Domains can be seeded via TenantConfig.Tenants and
// TenantConfig.Domains for embedded deployments. Operators
// running an admin-managed setup can leave both empty and
// populate via the admin TenantService RPCs.
type TenantConfig struct {
	Enabled          bool                        `yaml:"enabled"`
	Backend          string                      `yaml:"backend"` // memory | sqlite
	SQLite           TenantSQLiteConfig          `yaml:"sqlite"`
	LookupTimeout    time.Duration               `yaml:"lookup_timeout"`
	IncludeSuspended bool                        `yaml:"include_suspended"`
	Tenants          []TenantSeedConfig          `yaml:"tenants"`
	Domains          []TenantDomainConfig        `yaml:"domains"`
	SuspensionCheck  TenantSuspensionCheckConfig `yaml:"suspension_check"`
	UsageMetering    TenantUsageMeteringConfig   `yaml:"usage_metering"`
	ResourceQuota    TenantResourceQuotaConfig   `yaml:"resource_quota"`
}

// TenantResourceQuotaConfig selects the per-tenant resource quota backend and
// seeds operator-declared limits. Empty backend is normalized to disabled.
type TenantResourceQuotaConfig struct {
	Backend           string                             `yaml:"backend"` // disabled | memory | postgres
	CleanupInterval   time.Duration                      `yaml:"cleanup_interval"`
	Limits            []TenantQuotaSeedConfig            `yaml:"limits"`
	ProjectionIngress TenantQuotaProjectionIngressConfig `yaml:"projection_ingress"`
}

// TenantQuotaProjectionIngressConfig exposes the machine-only entitlement
// projection endpoint. Sources are versioned desired-state records and may be
// updated in place through the precompiled registry API.
type TenantQuotaProjectionIngressConfig struct {
	Enabled  bool                                `yaml:"enabled"`
	Audience string                              `yaml:"audience"`
	Sources  []TenantQuotaProjectionSourceConfig `yaml:"sources"`
}

type TenantQuotaProjectionSourceConfig = quotabinding.Source

// TenantQuotaSeedConfig declares one tenant's initial commercial limits.
// Zero values remain unlimited and may later be replaced by entitlement sync.
type TenantQuotaSeedConfig struct {
	TenantID     string `yaml:"tenant_id"`
	MaxClients   int    `yaml:"max_clients"`
	MaxUsers     int    `yaml:"max_users"`
	MaxSessions  int    `yaml:"max_sessions"`
	MaxTokenRate int    `yaml:"max_token_rate"`
}

func (c *Config) validateTenantResourceQuota() error {
	cfg := &c.Tenant.ResourceQuota
	cfg.Backend = strings.ToLower(strings.TrimSpace(cfg.Backend))
	if cfg.Backend == "" {
		cfg.Backend = "disabled"
	}
	if err := c.validateTenantQuotaBackend(); err != nil {
		return err
	}
	if err := validateTenantQuotaProjectionIngress(*cfg); err != nil {
		return err
	}
	if cfg.Backend == "disabled" {
		if len(cfg.Limits) > 0 {
			return fmt.Errorf("config: tenant.resource_quota.limits require an enabled backend")
		}
		return nil
	}
	return validateTenantQuotaSeeds(*cfg)
}

func validateTenantQuotaProjectionIngress(cfg TenantResourceQuotaConfig) error {
	ingress := cfg.ProjectionIngress
	if !ingress.Enabled {
		return nil
	}
	if cfg.Backend == "disabled" {
		return fmt.Errorf("config: tenant.resource_quota.projection_ingress requires an enabled quota backend")
	}
	if !quotabinding.ValidIdentity(ingress.Audience) || len(ingress.Sources) == 0 {
		return fmt.Errorf("config: tenant.resource_quota.projection_ingress audience and sources are required")
	}
	if _, err := quotabinding.NewRegistry(ingress.Sources); err != nil {
		return fmt.Errorf("config: tenant.resource_quota.projection_ingress sources: %w", err)
	}
	return nil
}

func (c *Config) validateTenantQuotaBackend() error {
	cfg := c.Tenant.ResourceQuota
	if cfg.CleanupInterval < 0 {
		return fmt.Errorf("config: tenant.resource_quota.cleanup_interval must not be negative")
	}
	switch cfg.Backend {
	case "disabled":
		return nil
	case "memory", "postgres":
	default:
		return fmt.Errorf("config: tenant.resource_quota.backend must be disabled, memory, or postgres, got %q", cfg.Backend)
	}
	if !c.Tenant.Enabled {
		return fmt.Errorf("config: tenant.resource_quota.backend=%s requires tenant.enabled=true", cfg.Backend)
	}
	if cfg.Backend == "memory" && c.Server.Topology.Mode == TopologyModeMulti {
		return fmt.Errorf("config: tenant.resource_quota.backend=memory is unsafe with server.topology.mode=multi; use postgres")
	}
	if cfg.Backend == "postgres" && !c.Postgres.Configured() {
		return fmt.Errorf("config: postgres.dsn required when tenant.resource_quota.backend=postgres")
	}
	return nil
}

func validateTenantQuotaSeeds(cfg TenantResourceQuotaConfig) error {
	seen := make(map[string]struct{}, len(cfg.Limits))
	for _, seed := range cfg.Limits {
		if _, duplicate := seen[seed.TenantID]; duplicate {
			return fmt.Errorf("config: duplicate tenant.resource_quota limit for tenant %q", seed.TenantID)
		}
		seen[seed.TenantID] = struct{}{}
		if err := core.ValidateQuotaTenantID(seed.TenantID); err != nil {
			return fmt.Errorf("config: tenant.resource_quota tenant_id %q: %w", seed.TenantID, err)
		}
		quota := core.TenantQuota{MaxClients: seed.MaxClients, MaxUsers: seed.MaxUsers,
			MaxSessions: seed.MaxSessions, MaxTokenRate: seed.MaxTokenRate}
		if err := core.ValidateTenantQuota(&quota); err != nil {
			return fmt.Errorf("config: tenant.resource_quota tenant %q: %w", seed.TenantID, err)
		}
	}
	return nil
}

// TenantUsageMeteringConfig opts into the per-tenant usage/metering report
// (GET /api/v1/admin/tenants/:id/usage, admin:read) via
// sso.WithTenantUsageAggregator. The sqlite aggregator reads the audit_events
// table, so its DSN is normally the audit SQLite DSN (audit.sqlite.dsn). Empty
// backend = endpoint not mounted (byte-identical).
type TenantUsageMeteringConfig struct {
	Backend string `yaml:"backend"` // "" (disabled) | memory | sqlite
	DSN     string `yaml:"dsn"`     // sqlite: the audit DB DSN (audit_events source)
}

// TenantSQLiteConfig is the SQLite backend's DSN.
type TenantSQLiteConfig struct {
	DSN string `yaml:"dsn"`
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
	// TokenStrategy binds this tenant to a registered token issuer/strategy
	// (sso.WithTenantTokenIssuer) — e.g. "jwt" or "session" — so the tenant's
	// tokens use that strategy instead of the server default. Empty = use the
	// default strategy. Must name a registered strategy or boot fails loud.
	TokenStrategy string `yaml:"token_strategy"`
}

// ConnectionsConfig wires per-organization enterprise connections for B2B
// home-realm discovery (sso.WithConnectionStore) and seeds them. When disabled,
// the /auth/home-realm endpoint is NOT mounted (byte-identical). Without this,
// the runnable binary had no way to populate connections at all — the home-realm
// feature was reachable only by SDK embedders calling Store.Upsert directly.
type ConnectionsConfig struct {
	Enabled            bool                     `yaml:"enabled"`
	Backend            string                   `yaml:"backend"` // memory | sqlite
	SQLite             ConnectionsSQLiteConfig  `yaml:"sqlite"`
	Connections        []ConnectionSeedConfig   `yaml:"connections"`
	DomainVerification DomainVerificationConfig `yaml:"domain_verification"`
	Probe              ConnectionsProbeConfig   `yaml:"probe"`
}

// ConnectionsProbeConfig bounds the admin-triggered reachability probe
// (POST /api/v1/admin/connections/:id/probe — OIDC discovery / SAML metadata
// fetch against the connection's configured upstream).
type ConnectionsProbeConfig struct {
	// Timeout bounds a single probe's HTTP round-trip. <=0 uses
	// connections.DefaultProbeTimeout (10s).
	Timeout time.Duration `yaml:"timeout"`
}

// DomainVerificationConfig gates DNS-TXT email-domain ownership proof before a
// runtime (admin-API) Upsert can steal another connection's already-VERIFIED
// domain from home-realm routing. Disabled by default: last-write-wins Upsert,
// byte-identical to the pre-feature behavior (a single-tenant deployment with a
// trusted admin has no attacker to defend against). Boot-time YAML-seeded
// connections are ALWAYS auto-verified regardless of this flag — the operator
// authoring the YAML is an equivalent trust level to a direct DB write.
type DomainVerificationConfig struct {
	Enabled      bool   `yaml:"enabled"`
	RecordPrefix string `yaml:"record_prefix"` // default connections.DefaultRecordPrefix
}

// ConnectionsSQLiteConfig is the SQLite backend's DSN.
type ConnectionsSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// ConnectionSeedConfig declares one enterprise connection to Upsert on boot.
// Config carries opaque protocol-specific settings (e.g. oidc_issuer,
// oidc_client_id, saml_metadata_url) the consuming authenticator interprets.
type ConnectionSeedConfig struct {
	ID          string            `yaml:"id"`
	TenantID    string            `yaml:"tenant_id"`
	Type        string            `yaml:"type"` // oidc | saml
	DisplayName string            `yaml:"display_name"`
	Domains     []string          `yaml:"domains"`
	Enabled     bool              `yaml:"enabled"`
	Config      map[string]string `yaml:"config"`
}

// TenantDomainConfig declares a hostname → tenant mapping.
type TenantDomainConfig struct {
	Hostname        string            `yaml:"hostname"`
	TenantID        string            `yaml:"tenant_id"`
	DefaultClientID string            `yaml:"default_client_id"`
	IsApex          bool              `yaml:"is_apex"`
	Branding        map[string]string `yaml:"branding"`
}

// PermissionsConfig configures role/menu authorization. When disabled,
// the /permissions/me, /menus/me, /roles/me endpoints reply 501.
//
// Backend selects which permissions.Provider implementation is wired:
// memory keeps the process-local map (single-replica only); sqlite
// shares roles + assignments + menus across the cluster (admin
// AddRole / AssignRoles / SetMenus on one replica surface on every
// replica's next lookup). Apps + UserRoles seeds run against the
// chosen backend at boot — duplicate seeds across replicas pointed
// at the same SQLite DSN deduplicate via the ON CONFLICT UPSERT
// the backend uses.

// validateRegionPolicyStore normalizes and validates region.policy_store.
// Empty backend is normalized to not wired (nil store → tenant-row-only
// residency, byte-identical). An invalid seed region ID fails boot loud —
// region IDs are exact-match governance keys, so a typo must never boot.
func (c *Config) validateRegionPolicyStore() error {
	cfg := &c.Region.PolicyStore
	cfg.Backend = strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch cfg.Backend {
	case "":
		if len(cfg.Seed) > 0 {
			return fmt.Errorf("config: region.policy_store.seed requires an enabled backend")
		}
		return nil
	case "memory", "sqlite":
	default:
		return fmt.Errorf("config: region.policy_store.backend must be memory or sqlite, got %q", cfg.Backend)
	}
	if cfg.Backend == "sqlite" && strings.TrimSpace(cfg.SQLite.DSN) == "" {
		return fmt.Errorf("config: region.policy_store.sqlite.dsn required when backend=sqlite")
	}
	seen := make(map[string]struct{}, len(cfg.Seed))
	for _, seed := range cfg.Seed {
		if seed.TenantID == "" {
			return fmt.Errorf("config: region.policy_store.seed tenant_id required")
		}
		if _, dup := seen[seed.TenantID]; dup {
			return fmt.Errorf("config: region.policy_store.seed duplicates tenant %q", seed.TenantID)
		}
		seen[seed.TenantID] = struct{}{}
		if seed.HomeRegion != "" {
			if err := region.ValidateID(region.ID(seed.HomeRegion)); err != nil {
				return fmt.Errorf("config: region.policy_store.seed tenant %q home_region: %w", seed.TenantID, err)
			}
		}
		for _, r := range seed.AllowedRegions {
			if err := region.ValidateID(region.ID(r)); err != nil {
				return fmt.Errorf("config: region.policy_store.seed tenant %q allowed_region: %w", seed.TenantID, err)
			}
		}
	}
	return nil
}
