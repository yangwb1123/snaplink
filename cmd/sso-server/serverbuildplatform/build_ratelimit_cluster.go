package serverbuildplatform

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/platform/cluster"

	clusteretcd "github.com/snaplink/sso/platform/cluster/etcd"

	"github.com/snaplink/sso/config"
	clustermemory "github.com/snaplink/sso/platform/cluster/memory"

	"github.com/snaplink/sso/infrastructure/defaultimpl"

	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/platform/registry"

	registryetcd "github.com/snaplink/sso/platform/registry/etcd"
	"github.com/snaplink/sso/platform/registry/memory"
	"github.com/snaplink/sso/platform/signingkeys"

	signingkeysetcd "github.com/snaplink/sso/platform/signingkeys/etcd"

	signingkeysmemory "github.com/snaplink/sso/platform/signingkeys/memory"
)

// BuildRateLimitPolicy translates RateLimitConfig into a ratelimit.Policy.
// Each prefix becomes its own Limiter (sized by per_sec + burst);
// Default kicks in for paths no prefix matches. A zero DefaultPerSec
// leaves Default nil (no limit on unmatched paths — useful when only
// a few hot endpoints need throttling). KeyByClientIDOrIP is used so
// HTTP-Basic-authenticated /token traffic buckets per-client, with
// IP as the fallback for unauthenticated paths.
//
// Backend choice:
//   - "" / "memory" — per-replica MemoryLimiter (default).
//   - "sqlite" — SQLiteLimiter against cfg.SQLite.DSN; each prefix
//     gets a distinct bucket_name so multiple rules can share one
//     DSN file without colliding.
func BuildRateLimitPolicy(cfg config.RateLimitConfig) (ratelimit.Policy, error) {
	p := ratelimit.Policy{Key: ratelimit.KeyByClientIDOrIP}
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "", "memory":
		if cfg.DefaultPerSec > 0 {
			p.Default = ratelimit.NewMemoryLimiter(cfg.DefaultPerSec, cfg.DefaultBurst)
		}
		for _, r := range cfg.Prefixes {
			p.Prefixes = append(p.Prefixes, ratelimit.PrefixRule{
				Prefix:  r.Prefix,
				Limiter: ratelimit.NewMemoryLimiter(r.PerSec, r.Burst),
			})
		}
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return ratelimit.Policy{}, errors.New("security.rate_limit.sqlite.dsn required when backend=sqlite")
		}
		if cfg.DefaultPerSec > 0 {
			lim, err := ratelimit.NewSQLiteLimiter(cfg.SQLite.DSN, cfg.DefaultPerSec, cfg.DefaultBurst, "default")
			if err != nil {
				return ratelimit.Policy{}, fmt.Errorf("rate_limit default sqlite: %w", err)
			}
			p.Default = lim
		}
		for _, r := range cfg.Prefixes {
			lim, err := ratelimit.NewSQLiteLimiter(cfg.SQLite.DSN, r.PerSec, r.Burst, r.Prefix)
			if err != nil {
				return ratelimit.Policy{}, fmt.Errorf("rate_limit prefix %q sqlite: %w", r.Prefix, err)
			}
			p.Prefixes = append(p.Prefixes, ratelimit.PrefixRule{
				Prefix:  r.Prefix,
				Limiter: lim,
			})
		}
	default:
		return ratelimit.Policy{}, fmt.Errorf("unknown security.rate_limit.backend %q", cfg.Backend)
	}
	return p, nil
}

// BuildRegistry materializes the service registry for cmd.
//
// Memory backend is per-process (no peer discovery, no TTL); etcd
// is cluster-shared via lease + KeepAlive. The etcd path is
// constructed here so the etcd transitive dep stays out of the
// registry SPI. Returns the kind ("memory" or "etcd") so caller
// can decide whether a /readyz check is meaningful (memory has no
// backend state to probe).
func BuildRegistry(cfg *config.RegistryConfig, logger spi.Logger) (registry.Registry, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "", "memory":
		logger.Info("service registry", "backend", "memory")
		return memory.New(), "memory", nil
	case "etcd":
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, "", errors.New("registry.etcd_endpoints required when registry.backend=etcd")
		}
		reg, err := registryetcd.New(registryetcd.Config{
			Endpoints:   cfg.EtcdEndpoints,
			Prefix:      cfg.EtcdPrefix,
			DialTimeout: cfg.EtcdDialTimeout,
			Username:    cfg.EtcdUsername,
			Password:    cfg.EtcdPassword,
		})
		if err != nil {
			return nil, "", fmt.Errorf("registry/etcd: %w", err)
		}
		logger.Info("service registry",
			"backend", "etcd",
			"endpoints", cfg.EtcdEndpoints,
			"prefix", cfg.EtcdPrefix)
		return reg, "etcd", nil
	default:
		return nil, "", fmt.Errorf("unknown registry.backend %q", cfg.Backend)
	}
}

// BuildInvalidationBus materializes the cross-replica cluster.Bus.
//
// Unset backend → nil bus: single-node deployments invalidate caches
// locally and need no bus, so this is the safe default. memory is
// per-process (a no-op for multi-replica); etcd is cluster-shared. The
// etcd path is constructed here so the transitive dep stays out of the
// cluster SPI, mirroring BuildRegistry. Returns the kind for logging;
// the bus is fail-open, so it intentionally gets no /readyz check.
func BuildInvalidationBus(cfg *config.ClusterBusConfig, logger spi.Logger) (cluster.Bus, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "":
		return nil, "", nil
	case "memory":
		logger.Info("invalidation bus", "backend", "memory")
		return clustermemory.New(), "memory", nil
	case "etcd":
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, "", errors.New("cluster.bus.etcd_endpoints required when cluster.bus.backend=etcd")
		}
		bus, err := clusteretcd.New(clusteretcd.Config{
			Endpoints:   cfg.EtcdEndpoints,
			Prefix:      cfg.EtcdPrefix,
			DialTimeout: cfg.EtcdDialTimeout,
			EventTTL:    cfg.EtcdEventTTL,
			Username:    cfg.EtcdUsername,
			Password:    cfg.EtcdPassword,
		})
		if err != nil {
			return nil, "", fmt.Errorf("cluster/etcd: %w", err)
		}
		logger.Info("invalidation bus", "backend", "etcd",
			"endpoints", cfg.EtcdEndpoints, "prefix", cfg.EtcdPrefix)
		return bus, "etcd", nil
	default:
		return nil, "", fmt.Errorf("unknown cluster.bus.backend %q", cfg.Backend)
	}
}

// BuildSigningKeyRegistry constructs the shared signing-key registry for
// leaderless multi-replica JWKS aggregation. Returns (nil, "", nil) when
// disabled. memory is per-process (single-node / test); etcd is cluster-
// shared — each replica announces its public keys under a lease and peers
// Watch + adopt, so a token signed on one replica verifies on every replica.
// The etcd path is constructed here so the transitive dep stays out of the
// signingkeys SPI, mirroring BuildInvalidationBus. The registry is fail-open
// (a dropped announcement only narrows a verify-set back toward local keys),
// so it intentionally gets no /readyz check.
func BuildSigningKeyRegistry(cfg *config.SigningKeyRegistryConfig, logger spi.Logger) (signingkeys.Registry, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "":
		return nil, "", nil
	case "memory":
		logger.Info("signing key registry", "backend", "memory")
		return signingkeysmemory.New(), "memory", nil
	case "etcd":
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, "", errors.New("keys.signing_key_registry.etcd_endpoints required when backend=etcd")
		}
		reg, err := signingkeysetcd.New(signingkeysetcd.Config{
			Endpoints:   cfg.EtcdEndpoints,
			Prefix:      cfg.EtcdPrefix,
			DialTimeout: cfg.EtcdDialTimeout,
			// LeaseTTL is the backend fallback when an announcement's
			// LeaseSeconds is 0; the Server derives LeaseSeconds from the same
			// keys.signing_key_registry.lease_ttl, so the two agree.
			LeaseTTL: cfg.LeaseTTL,
			Username: cfg.EtcdUsername,
			Password: cfg.EtcdPassword,
		})
		if err != nil {
			return nil, "", fmt.Errorf("signingkeys/etcd: %w", err)
		}
		logger.Info("signing key registry", "backend", "etcd",
			"endpoints", cfg.EtcdEndpoints, "prefix", cfg.EtcdPrefix)
		return reg, "etcd", nil
	default:
		return nil, "", fmt.Errorf("unknown keys.signing_key_registry.backend %q", cfg.Backend)
	}
}

// SigningKeyRotationConfig translates the YAML rotation config into a
// defaultimpl.RotationConfig (without OnRotate, which the caller
// attaches), returning ok=false when rotation is disabled or
// misconfigured (interval <= 0). Pure so it is unit-testable.
func SigningKeyRotationConfig(cfg config.KeyRotationConfig) (defaultimpl.RotationConfig, bool) {
	if !cfg.Enabled || cfg.Interval <= 0 {
		return defaultimpl.RotationConfig{}, false
	}
	return defaultimpl.RotationConfig{
		Interval:    cfg.Interval,
		GracePeriod: cfg.GracePeriod,
	}, true
}

// ResolveServiceID derives the registry Service.ID. Explicit YAML
// wins; otherwise we synthesize from the issuer + the host's short
// hostname so two replicas of the same issuer don't write the same
// etcd key and clobber each other's lease. Hostname lookup failure
// falls back to a fixed suffix — better stable-ish than panic.
func ResolveServiceID(explicit, issuer string) string {
	if id := strings.TrimSpace(explicit); id != "" {
		return id
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		return issuer + "-1"
	}
	if idx := strings.IndexByte(host, '.'); idx > 0 {
		host = host[:idx]
	}
	return issuer + "-" + host
}
