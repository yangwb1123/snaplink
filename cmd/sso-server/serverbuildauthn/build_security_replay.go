package serverbuildauthn

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystorecredential"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	postgresbackend "github.com/snaplink/sso/infrastructure/postgres"
	redisbackend "github.com/snaplink/sso/infrastructure/redis"

	"github.com/snaplink/sso/shared/security"
)

func BuildPairwiseSubjectStore(cfg config.PairwiseSubjectsConfig, pg *sql.DB, dialect postgresbackend.Dialect) (security.PairwiseSubjectStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return security.NewMemoryPairwiseSubjectStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("server.pairwise_subjects.sqlite.dsn required when backend=sqlite")
		}
		store, err := sqlitestores.NewPairwiseSubjectStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	case "postgres":
		if pg == nil {
			return nil, "", errors.New("server.pairwise_subjects.backend=postgres but no postgres block configured (set postgres.dsn)")
		}
		store, err := postgresbackend.NewPairwiseSubjectStoreWithDB(pg, dialect)
		if err != nil {
			return nil, "", err
		}
		return store, "postgres (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown server.pairwise_subjects.backend %q (supported: memory, sqlite, postgres)", cfg.Backend)
	}
}

// BuildAccountLockout picks the lockout backend. memory keeps the
// single-replica defense; sqlite shares the failure counter so an
// attacker rotating across replicas can't stay under each replica's
// local threshold. Policy overrides (MaxFailures / LockoutDuration
// / FailureWindow) are applied identically to both backends.
func BuildAccountLockout(cfg config.AccountLockoutConfig, rdb goredis.Cmdable) (security.AccountLockout, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		l := security.NewMemoryAccountLockout()
		if cfg.MaxFailures > 0 {
			l.MaxFailures = cfg.MaxFailures
		}
		if cfg.LockoutDuration > 0 {
			l.LockoutDuration = cfg.LockoutDuration
		}
		if cfg.FailureWindow > 0 {
			l.FailureWindow = cfg.FailureWindow
		}
		return l, "memory (single-replica only)", nil
	case "redis":
		return buildRedisLockout(cfg, rdb)
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("security.account_lockout.sqlite.dsn required when backend=sqlite")
		}
		l, err := sqlitestores.NewAccountLockout(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		if cfg.MaxFailures > 0 {
			l.MaxFailures = cfg.MaxFailures
		}
		if cfg.LockoutDuration > 0 {
			l.LockoutDuration = cfg.LockoutDuration
		}
		if cfg.FailureWindow > 0 {
			l.FailureWindow = cfg.FailureWindow
		}
		return l, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown security.account_lockout.backend %q", cfg.Backend)
	}
}

// buildRedisLockout constructs the Redis-backed lockout (atomic INCR+threshold
// Lua over hash-tagged per-subject keys, so the failure counter is
// cluster-shared) and applies the same policy overrides as the other backends.
func buildRedisLockout(cfg config.AccountLockoutConfig, rdb goredis.Cmdable) (security.AccountLockout, string, error) {
	if rdb == nil {
		return nil, "", errors.New("security.account_lockout.backend=redis but no redis block configured (set redis.addrs)")
	}
	l := redisbackend.NewAccountLockout(rdb)
	if cfg.MaxFailures > 0 {
		l.MaxFailures = cfg.MaxFailures
	}
	if cfg.LockoutDuration > 0 {
		l.LockoutDuration = cfg.LockoutDuration
	}
	if cfg.FailureWindow > 0 {
		l.FailureWindow = cfg.FailureWindow
	}
	return l, "redis (cluster-shared)", nil
}

// BuildSubjectClientIndex picks the security.SubjectClientIndex backend that
// drives OIDC BCL multi-RP fan-out. memory keeps the single-replica
// story; sqlite shares the index so a logout reaching any replica
// fans out to every client a subject has touched cluster-wide.
func BuildSubjectClientIndex(cfg config.BCLIndexConfig, rdb goredis.Cmdable) (security.SubjectClientIndex, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return defaultimpl.NewMemorySubjectClientIndex(), "memory (single-replica only)", nil
	case "redis":
		// One SET per subject (SADD/SMEMBERS/SREM, single-key), so the active-
		// client index is cluster-shared and a logout reaching any replica fans
		// out to every RP the subject touched.
		if rdb == nil {
			return nil, "", errors.New("backchannel_logout.index.backend=redis but no redis block configured (set redis.addrs)")
		}
		return redisbackend.NewSubjectClientIndex(rdb), "redis (cluster-shared)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("backchannel_logout.index.sqlite.dsn required when backend=sqlite")
		}
		idx, err := sqlitestores.NewSubjectClientIndex(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return idx, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown backchannel_logout.index.backend %q", cfg.Backend)
	}
}

// BuildJTIReplayStore picks the JTI replay backend. memory keeps
// the single-replica defense story; sqlite shares the seen-set
// across the cluster so a replay routed to a different replica still
// gets rejected.
func BuildJTIReplayStore(cfg config.JTIReplayConfig, rdb goredis.Cmdable) (security.JTIReplayStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return newBoundedMemoryJTIStore(cfg), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("security.jti_replay.sqlite.dsn required when backend=sqlite")
		}
		store, err := sqlitestores.NewJTIReplayStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	case "redis":
		if rdb == nil {
			return nil, "", errors.New("security.jti_replay.backend=redis but no redis block configured (set redis.addrs)")
		}
		// SET NX EX first-sighting — master-pinned (do not route to replicas):
		// async lag could let a replayed jti momentarily evade detection.
		return redisbackend.NewJTIReplayStore(rdb), "redis (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown security.jti_replay.backend %q (supported: memory, sqlite, redis)", cfg.Backend)
	}
}

// buildAuthenticatorReplayStore resolves the replay-defense store the keypair
// (nonce) and TOTP (consumed-code) authenticators record against. Unlike the
// DPoP/JAR/assertion jti store it is ALWAYS present: the keypair signature and
// TOTP code each replay within their bounded skew/step window, so a shipped
// binary that omits the store is replay-vulnerable by default. When the
// operator already opted into jti replay protection we reuse that backend (so
// sqlite stays cluster-shared and the defense doesn't fork across replicas);
// otherwise we default to an in-memory store so the out-of-the-box binary is
// safe on a single replica. Reuses the existing security.JTIReplayStore SPI —
// a nonce / consumed (user, step) is just another "have I seen this before"
// check. mode is for the boot log.
func buildAuthenticatorReplayStore(cfg config.JTIReplayConfig, rdb goredis.Cmdable) (security.JTIReplayStore, string, error) {
	if cfg.Enabled {
		return BuildJTIReplayStore(cfg, rdb)
	}
	return newBoundedMemoryJTIStore(cfg), "memory (default; enable security.jti_replay for cluster-shared)", nil
}

// newBoundedMemoryJTIStore constructs the in-process JTI store and applies
// cfg's MaxEntries/ReapInterval — shared by BuildJTIReplayStore's memory
// case and buildAuthenticatorReplayStore's fallback so both call sites
// honor the same config fields identically.
func newBoundedMemoryJTIStore(cfg config.JTIReplayConfig) *memorystorecredential.MemoryJTIReplayStore {
	s := defaultimpl.NewMemoryJTIReplayStore()
	s.MaxEntries = cfg.MaxEntries
	if cfg.ReapInterval > 0 {
		s.StartReaper(cfg.ReapInterval)
	}
	return s
}
