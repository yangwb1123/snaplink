package serverbuildstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/yangwb1123/snaplink/shared/spi"

	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/connections"

	"github.com/yangwb1123/snaplink/domains/region"
	regionmemory "github.com/yangwb1123/snaplink/domains/region/memory"
	regionsqlite "github.com/yangwb1123/snaplink/domains/region/sqlite"

	connectionssqlite "github.com/yangwb1123/snaplink/domains/connections/sqlite"

	"github.com/yangwb1123/snaplink/platform/geo"

	"github.com/yangwb1123/snaplink/domains/metering"
	geostatic "github.com/yangwb1123/snaplink/platform/geo/static"

	meteringmemory "github.com/yangwb1123/snaplink/domains/metering/memory"

	meteringsqlite "github.com/yangwb1123/snaplink/domains/metering/sqlite"

	"github.com/yangwb1123/snaplink/shared/security/peertrust"

	"github.com/yangwb1123/snaplink/domains/tenant"
)

// BuildTenantStore materialises the tenant.Store from TenantConfig
// and seeds any declared tenants + domains. Returns (nil, nil)
// when tenant.enabled=false so cmd can pass the result to
// sso.WithTenantStore unconditionally (the option no-ops on nil).
// BuildTenantUsageAggregator selects the per-tenant usage metering backend.
// Empty backend returns (nil, nil) — the usage endpoint stays unmounted. The
// sqlite aggregator reads the audit_events table, so its DSN is normally the
// audit SQLite DSN.
func BuildTenantUsageAggregator(cfg config.TenantUsageMeteringConfig) (metering.Aggregator, error) {
	switch strings.ToLower(cfg.Backend) {
	case "":
		return nil, nil
	case "memory":
		return meteringmemory.NewAggregator(), nil
	case "sqlite":
		if cfg.DSN == "" {
			return nil, errors.New("tenant.usage_metering.dsn required when backend=sqlite (point it at the audit DB)")
		}
		return meteringsqlite.New(cfg.DSN)
	default:
		return nil, fmt.Errorf("unknown tenant.usage_metering.backend %q", cfg.Backend)
	}
}

func BuildTenantStore(cfg *config.Config, logger spi.Logger, pg *sql.DB, dialect postgresbackend.Dialect) (tenant.Store, error) {
	if !cfg.Tenant.Enabled {
		return nil, nil
	}
	store, err := buildTenantStoreBackend(cfg.Tenant, logger, pg, dialect)
	if err != nil {
		return nil, err
	}
	if err := seedTenantStore(store, cfg.Tenant); err != nil {
		_ = store.Close()
		return nil, err
	}
	logger.Info("tenant seed complete",
		"tenants", len(cfg.Tenant.Tenants),
		"domains", len(cfg.Tenant.Domains))
	return store, nil
}

// BuildConnectionStore materialises the connections.Store from
// ConnectionsConfig and seeds it. Returns (nil, nil) when disabled — cmd then
// skips sso.WithConnectionStore, so the /auth/home-realm endpoint is not mounted
// (byte-identical). This is the only way the runnable binary can populate B2B
// enterprise connections; without it the home-realm feature was SDK-only.
func BuildConnectionStore(cfg *config.Config, logger spi.Logger) (connections.Store, error) {
	if !cfg.Connections.Enabled {
		return nil, nil
	}
	opts := connectionStoreOptions(cfg.Connections.DomainVerification)
	store, err := buildConnectionBackend(cfg.Connections, logger, opts)
	if err != nil {
		return nil, err
	}
	if err := seedConnections(store, cfg.Connections); err != nil {
		if closer, ok := store.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, err
	}
	logger.Info("connection seed complete", "connections", len(cfg.Connections.Connections))
	return store, nil
}

// connectionStoreOptions maps the domain-verification config onto store options.
func connectionStoreOptions(dv config.DomainVerificationConfig) []connections.StoreOption {
	return []connections.StoreOption{
		connections.WithDomainVerificationRequired(dv.Enabled),
		connections.WithDomainVerificationRecordPrefix(dv.RecordPrefix),
	}
}

func buildConnectionBackend(cfg config.ConnectionsConfig, logger spi.Logger, opts []connections.StoreOption) (connections.Store, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		logger.Info("connection store: memory (in-process)")
		return connections.NewMemoryStore(opts...), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("connections.sqlite.dsn required when connections.backend=sqlite")
		}
		s, err := connectionssqlite.New(cfg.SQLite.DSN, opts...)
		if err != nil {
			return nil, fmt.Errorf("connections sqlite: %w", err)
		}
		logger.Info("connection store: sqlite (cluster-shared)", "dsn", cfg.SQLite.DSN)
		return s, nil
	default:
		return nil, fmt.Errorf("unknown connections.backend %q (supported: memory, sqlite)", cfg.Backend)
	}
}

// seedConnections Upserts each YAML-declared connection. A seeded connection is
// operator-authored (trusted like a direct DB write), so its domains are
// auto-verified when runtime verification is required — otherwise a seeded
// connection would never route until an admin ran the DNS challenge.
func seedConnections(store connections.Store, cfg config.ConnectionsConfig) error {
	ctx := context.Background()
	for _, c := range cfg.Connections {
		if err := store.Upsert(ctx, &connections.Connection{
			ID: c.ID, TenantID: c.TenantID, Type: connections.ConnectionType(c.Type),
			DisplayName: c.DisplayName, Domains: c.Domains, Enabled: c.Enabled, Config: c.Config,
		}); err != nil {
			return fmt.Errorf("seed connection %q: %w", c.ID, err)
		}
		if !cfg.DomainVerification.Enabled {
			continue
		}
		for _, dm := range c.Domains {
			if strings.TrimSpace(dm) == "" {
				continue
			}
			if err := store.VerifyDomain(ctx, c.ID, dm); err != nil {
				return fmt.Errorf("seed verify %q/%q: %w", c.ID, dm, err)
			}
		}
	}
	return nil
}

// BuildGeoProvider materialises the geo.Provider from GeoConfig.
// Returns nil when geo.enabled=false so cmd can pass the result to
// sso.WithGeoProvider unconditionally (the option no-ops on nil).
func BuildGeoProvider(cfg *config.Config, logger spi.Logger) (geo.Provider, error) {
	if !cfg.Geo.Enabled {
		return nil, nil
	}
	switch strings.ToLower(cfg.Geo.Backend) {
	case "", "static":
		p := geostatic.New()
		for _, e := range cfg.Geo.Static.Entries {
			if err := p.Add(e.CIDR, geo.GeoInfo{
				CountryCode:         e.CountryCode,
				Region:              e.Region,
				City:                e.City,
				TimeZone:            e.TimeZone,
				RecommendedLanguage: e.RecommendedLanguage,
			}); err != nil {
				return nil, fmt.Errorf("geo static entry %q: %w", e.CIDR, err)
			}
		}
		logger.Info("geo provider: static", "entries", p.Len())
		return p, nil
	default:
		return nil, fmt.Errorf("unknown geo.backend %q", cfg.Geo.Backend)
	}
}

// BuildRegionResolver materialises the region.Resolver from RegionConfig.
// Returns nil when NEITHER ServingRegion NOR HeaderName is configured so cmd
// can skip WithRegionMiddleware entirely (the middleware is then NOT installed
// → byte-identical to a pre-region build). Mirrors BuildGeoProvider's
// nil-when-disabled discipline.
//
// When configured it builds a ChainResolver that tries the trusted header
// FIRST (a regional edge/mesh pins traffic via HeaderName, anti-injection
// allowlisted by AllowedRegions), then falls back to the pinned ServingRegion.
// The HeaderResolver's Default is the pinned region too, so a single-region
// deployment that sets only ServingRegion still resolves every request to it.
//
// peerTrust (the compiled security.trusted_proxies checker; nil when the
// knob is unset) gates the header path: a direct peer outside the trusted
// CIDRs supplied the region header itself, so it resolves as if absent.
func BuildRegionResolver(cfg *config.Config, peerTrust *peertrust.Checker) region.Resolver {
	servingRegion := region.ID(cfg.Region.ServingRegion)
	if servingRegion == "" && cfg.Region.HeaderName == "" {
		return nil
	}
	var allowed []region.ID
	if len(cfg.Region.AllowedRegions) > 0 {
		allowed = make([]region.ID, len(cfg.Region.AllowedRegions))
		for i, r := range cfg.Region.AllowedRegions {
			allowed[i] = region.ID(r)
		}
	}
	return region.ChainResolver{Resolvers: []region.Resolver{
		region.HeaderResolver{
			Header:    cfg.Region.HeaderName,
			Allowed:   allowed,
			Default:   servingRegion,
			PeerTrust: peerTrust,
		},
		region.ConfigPinnedResolver{Region: servingRegion},
	}}
}

// BootstrapLogger adapts spi.Logger to bootstrap.Logger (Info/Error pair).
type BootstrapLogger struct{ Inner spi.Logger }

func (b BootstrapLogger) Info(msg string, kv ...any)  { b.Inner.Info(msg, kv...) }
func (b BootstrapLogger) Error(msg string, kv ...any) { b.Inner.Error(msg, kv...) }

// BuildRegionPolicyStore materialises the region.PolicyStore from
// region.policy_store config. Returns (nil, nil) when the backend is empty —
// cmd passes the result to sso.WithResidencyPolicyStore unconditionally (the
// option no-ops on nil, keeping the tenant-row-only path byte-identical).
// Seed entries are applied at build; an invalid seed region ID fails boot
// loud through the same Set path the stores enforce.
func BuildRegionPolicyStore(cfg *config.Config, logger spi.Logger) (region.PolicyStore, error) {
	rc := cfg.Region.PolicyStore
	switch rc.Backend {
	case "":
		return nil, nil
	case "memory":
		logger.Info("region policy store: memory (in-process)")
		store := regionmemory.New()
		if err := seedRegionPolicies(store, rc.Seed); err != nil {
			return nil, err
		}
		return store, nil
	case "sqlite":
		if strings.TrimSpace(rc.SQLite.DSN) == "" {
			return nil, errors.New("region.policy_store.sqlite.dsn required when backend=sqlite")
		}
		store, err := regionsqlite.New(rc.SQLite.DSN)
		if err != nil {
			return nil, fmt.Errorf("region policy store sqlite: %w", err)
		}
		if err := seedRegionPolicies(store, rc.Seed); err != nil {
			_ = store.Close()
			return nil, err
		}
		logger.Info("region policy store: sqlite (cluster-shared)", "dsn", rc.SQLite.DSN)
		return store, nil
	default:
		return nil, fmt.Errorf("unknown region.policy_store.backend %q (supported: memory, sqlite)", rc.Backend)
	}
}

// seedRegionPolicies applies the YAML-declared policy seeds, failing boot
// loud on any invalid entry (config validation already rejects malformed
// region IDs; the store Set is the second line of defense).
func seedRegionPolicies(store region.PolicyStore, seeds []config.RegionPolicySeedConfig) error {
	writer, ok := store.(interface {
		Set(ctx context.Context, tenantID string, p region.ResidencyPolicy) error
	})
	if !ok {
		return errors.New("region policy store: backend does not support seeding")
	}
	ctx := context.Background()
	for _, seed := range seeds {
		allowed := make([]region.ID, len(seed.AllowedRegions))
		for i, r := range seed.AllowedRegions {
			allowed[i] = region.ID(r)
		}
		if err := writer.Set(ctx, seed.TenantID, region.ResidencyPolicy{
			HomeRegion:     region.ID(seed.HomeRegion),
			AllowedRegions: allowed,
			EnforceWrites:  seed.EnforceWrites,
		}); err != nil {
			return fmt.Errorf("seed region policy for tenant %q: %w", seed.TenantID, err)
		}
	}
	return nil
}
