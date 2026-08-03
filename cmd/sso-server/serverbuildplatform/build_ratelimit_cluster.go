package serverbuildplatform

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/shared/spi"

	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"

	"github.com/yangwb1123/snaplink/platform/cluster"

	clusteretcd "github.com/yangwb1123/snaplink/platform/cluster/etcd"

	"github.com/yangwb1123/snaplink/config"
	clustermemory "github.com/yangwb1123/snaplink/platform/cluster/memory"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"

	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/platform/registry"

	registryetcd "github.com/yangwb1123/snaplink/platform/registry/etcd"
	"github.com/yangwb1123/snaplink/platform/registry/memory"
	"github.com/yangwb1123/snaplink/platform/signingkeys"

	signingkeysetcd "github.com/yangwb1123/snaplink/platform/signingkeys/etcd"

	signingkeysmemory "github.com/yangwb1123/snaplink/platform/signingkeys/memory"
)

// BuildRateLimitPolicy translates RateLimitConfig into a ratelimit.Policy.
// Each prefix becomes its own Limiter (sized by per_sec + burst);
// Default kicks in for paths no prefix matches. A zero DefaultPerSec
// leaves Default nil (no limit on unmatched paths — useful when only
// a few hot endpoints need throttling). The bucket is keyed by
// KeyByClientIP (the edge-validated source IP): the limiter runs BEFORE
// client auth, so keying on the unverified HTTP-Basic client_id would let
// a single source rotate it to escape all throttling.
//
// Backend choice:
//   - "" / "memory" — per-replica MemoryLimiter (default).
//   - "sqlite" — SQLiteLimiter against cfg.SQLite.DSN; each prefix
//     gets a distinct bucket_name so multiple rules can share one
//     DSN file without colliding.
func BuildRateLimitPolicy(cfg config.RateLimitConfig, rdb goredis.Cmdable) (ratelimit.Policy, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return memoryRateLimitPolicy(cfg), nil
	case "redis":
		return redisRateLimitPolicy(cfg, rdb)
	case "sqlite":
		return sqliteRateLimitPolicy(cfg)
	default:
		return ratelimit.Policy{}, fmt.Errorf("unknown security.rate_limit.backend %q (supported: memory, sqlite, redis)", cfg.Backend)
	}
}

// memoryRateLimitPolicy builds per-replica MemoryLimiters (the default). Not
// cluster-shared — the effective limit is N x configured across N replicas, so
// prefer redis/sqlite for a multi-replica fleet.
func memoryRateLimitPolicy(cfg config.RateLimitConfig) ratelimit.Policy {
	p := ratelimit.Policy{Key: ratelimit.KeyByClientIP}
	if cfg.DefaultPerSec > 0 {
		p.Default = newMemoryLimiterPruned(cfg.DefaultPerSec, cfg.DefaultBurst, cfg.PruneInterval)
	}
	for _, r := range cfg.Prefixes {
		p.Prefixes = append(p.Prefixes, ratelimit.PrefixRule{
			Prefix:  r.Prefix,
			Limiter: newMemoryLimiterPruned(r.PerSec, r.Burst, cfg.PruneInterval),
		})
	}
	return p
}

// newMemoryLimiterPruned builds a MemoryLimiter and, when interval is
// positive, starts its background pruner (see RateLimitConfig.PruneInterval)
// instead of leaving it on the default sampled inline prune.
func newMemoryLimiterPruned(perSec float64, burst int, interval time.Duration) *ratelimit.MemoryLimiter {
	lim := ratelimit.NewMemoryLimiter(perSec, burst)
	if interval > 0 {
		lim.StartPruner(interval)
	}
	return lim
}

// redisRateLimitPolicy builds shared cluster-wide buckets. Each bucket is a
// single key, so the limiter's Lua stays single-slot on Redis Cluster.
// Fail-open on a redis error is the Limiter's contract — an attacker must not be
// able to DoS the fleet into lockout by killing Redis.
func redisRateLimitPolicy(cfg config.RateLimitConfig, rdb goredis.Cmdable) (ratelimit.Policy, error) {
	if rdb == nil {
		return ratelimit.Policy{}, errors.New("security.rate_limit.backend=redis but no redis block configured (set redis.addrs)")
	}
	p := ratelimit.Policy{Key: ratelimit.KeyByClientIP}
	if cfg.DefaultPerSec > 0 {
		p.Default = redisbackend.NewLimiterFromRate(rdb, cfg.DefaultPerSec, cfg.DefaultBurst, "default")
	}
	for _, r := range cfg.Prefixes {
		p.Prefixes = append(p.Prefixes, ratelimit.PrefixRule{
			Prefix:  r.Prefix,
			Limiter: redisbackend.NewLimiterFromRate(rdb, r.PerSec, r.Burst, r.Prefix),
		})
	}
	return p, nil
}

// sqliteRateLimitPolicy builds cluster-shared SQLiteLimiters; each prefix gets a
// distinct bucket_name so multiple rules share one DSN file without colliding.
func sqliteRateLimitPolicy(cfg config.RateLimitConfig) (ratelimit.Policy, error) {
	if cfg.SQLite.DSN == "" {
		return ratelimit.Policy{}, errors.New("security.rate_limit.sqlite.dsn required when backend=sqlite")
	}
	p := ratelimit.Policy{Key: ratelimit.KeyByClientIP}
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
		p.Prefixes = append(p.Prefixes, ratelimit.PrefixRule{Prefix: r.Prefix, Limiter: lim})
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
// per-process (a no-op for multi-replica); etcd is cluster-shared; redis
// is cluster-shared via pub/sub over the one shared Redis client (the
// same client every redis-backed store uses — one pool, one HA story).
// The etcd/redis paths are constructed here so the transitive deps stay
// out of the cluster SPI, mirroring BuildRegistry. Returns the kind for
// logging; the bus is fail-open, so it intentionally gets no /readyz check.
//
// instanceID arms the redis backend's publisher self-skip (a replica must
// not re-apply its own mutations; see redis.WithInstanceID). It is ignored
// by the memory/etcd branches, whose wire behavior stays byte-identical.
func BuildInvalidationBus(cfg *config.ClusterBusConfig, rdb goredis.UniversalClient, instanceID string, logger spi.Logger) (cluster.Bus, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "":
		return nil, "", nil
	case "memory":
		logger.Info("invalidation bus", "backend", "memory")
		return clustermemory.New(), "memory", nil
	case "redis":
		if rdb == nil {
			return nil, "", errors.New("cluster.bus.backend=redis but no redis block configured (set redis.addrs)")
		}
		opts := []redisbackend.BusOption{redisbackend.WithChannel(cfg.RedisChannel)} // empty ⇒ default inside
		if instanceID != "" {
			opts = append(opts, redisbackend.WithInstanceID(instanceID))
		}
		bus := redisbackend.NewBus(rdb, opts...)
		logger.Info("invalidation bus", "backend", "redis",
			"channel", bus.Channel(), "instance_id", bus.InstanceID())
		return bus, "redis", nil
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
// signingkeys SPI, mirroring BuildInvalidationBus. Peer-key adoption is
// fail-open (a dropped announcement only narrows a verify-set back toward
// local keys), but the etcd backend's publish lease is not: while its
// KeepAlive is degraded this replica's keys are missing from peers' JWKS, so
// wireSigningKeyRegistryOpts registers the backend's ReadyzCheck with /readyz.
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

// ResolveReplicaID derives the per-replica identity shared by the
// signing-key registry announcements and the invalidation-bus self-skip
// filter. An explicit keys.signing_key_registry.replica_id wins; otherwise
// the service-registry id (explicit registry.service_id, else issuer + short
// hostname) — so two replicas of one issuer never share an id.
func ResolveReplicaID(replicaID, serviceID, issuer string) string {
	if id := strings.TrimSpace(replicaID); id != "" {
		return id
	}
	return ResolveServiceID(serviceID, issuer)
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
