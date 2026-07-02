package config

import "time"

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
	ServingRegion          string        `yaml:"serving_region"`
	HeaderName             string        `yaml:"header_name"`
	AllowedRegions         []string      `yaml:"allowed_regions"`
	ResidencyCheckCacheTTL time.Duration `yaml:"residency_check_cache_ttl"`
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
