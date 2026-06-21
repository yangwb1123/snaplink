package serverbuildstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/connections"

	connectionssqlite "github.com/snaplink/sso/domains/connections/sqlite"

	"github.com/snaplink/sso/platform/geo"

	"github.com/snaplink/sso/domains/metering"
	geostatic "github.com/snaplink/sso/platform/geo/static"

	meteringmemory "github.com/snaplink/sso/domains/metering/memory"

	meteringsqlite "github.com/snaplink/sso/domains/metering/sqlite"

	"github.com/snaplink/sso/domains/region"

	"github.com/snaplink/sso/domains/tenant"
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
		return meteringmemory.New(), nil
	case "sqlite":
		if cfg.DSN == "" {
			return nil, errors.New("tenant.usage_metering.dsn required when backend=sqlite (point it at the audit DB)")
		}
		return meteringsqlite.New(cfg.DSN)
	default:
		return nil, fmt.Errorf("unknown tenant.usage_metering.backend %q", cfg.Backend)
	}
}

func BuildTenantStore(cfg *config.Config, logger spi.Logger) (tenant.Store, error) {
	if !cfg.Tenant.Enabled {
		return nil, nil
	}
	store, err := buildTenantStoreBackend(cfg.Tenant, logger)
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
	var store connections.Store
	switch strings.ToLower(cfg.Connections.Backend) {
	case "", "memory":
		store = connections.NewMemoryStore()
		logger.Info("connection store: memory (in-process)")
	case "sqlite":
		if cfg.Connections.SQLite.DSN == "" {
			return nil, errors.New("connections.sqlite.dsn required when connections.backend=sqlite")
		}
		s, err := connectionssqlite.New(cfg.Connections.SQLite.DSN)
		if err != nil {
			return nil, fmt.Errorf("connections sqlite: %w", err)
		}
		store = s
		logger.Info("connection store: sqlite (cluster-shared)", "dsn", cfg.Connections.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown connections.backend %q (supported: memory, sqlite)", cfg.Connections.Backend)
	}

	ctx := context.Background()
	for _, c := range cfg.Connections.Connections {
		if err := store.Upsert(ctx, &connections.Connection{
			ID:          c.ID,
			TenantID:    c.TenantID,
			Type:        connections.ConnectionType(c.Type),
			DisplayName: c.DisplayName,
			Domains:     c.Domains,
			Enabled:     c.Enabled,
			Config:      c.Config,
		}); err != nil {
			if closer, ok := store.(io.Closer); ok {
				_ = closer.Close()
			}
			return nil, fmt.Errorf("seed connection %q: %w", c.ID, err)
		}
	}
	logger.Info("connection seed complete", "connections", len(cfg.Connections.Connections))
	return store, nil
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
func BuildRegionResolver(cfg *config.Config) region.Resolver {
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
			Header:  cfg.Region.HeaderName,
			Allowed: allowed,
			Default: servingRegion,
		},
		region.ConfigPinnedResolver{Region: servingRegion},
	}}
}

// BootstrapLogger adapts spi.Logger to bootstrap.Logger (Info/Error pair).
type BootstrapLogger struct{ Inner spi.Logger }

func (b BootstrapLogger) Info(msg string, kv ...any)  { b.Inner.Info(msg, kv...) }
func (b BootstrapLogger) Error(msg string, kv ...any) { b.Inner.Error(msg, kv...) }
