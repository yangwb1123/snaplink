package serverbuildstore

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/protocols/oauth"

	"github.com/yangwb1123/snaplink/config"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"

	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"
)

// errRedisNotConfigured is the shared boot error for a backend:redis selection
// with no redis block (no shared client was built). One message shape across
// every redis-capable store dispatcher in this package.
func errRedisNotConfigured(domain string) error {
	return fmt.Errorf("%s.backend=redis but no redis block configured (set redis.addrs)", domain)
}

// BuildAuthCodeStore / BuildRefreshTokenStore / BuildDeviceCodeStore
// pick between memory + sqlite + postgres per cfg.Backend. SQLite needs a
// DSN; postgres reuses the shared pool threaded from the postgres: block;
// memory needs nothing. Each SQLite call opens its own connection pool —
// for SQLite that's fine (OS-level file lock coordinates).
func BuildAuthCodeStore(cfg config.OAuthConfig, rdb goredis.Cmdable, pgDB *sql.DB, pgDialect postgresbackend.Dialect) (oauth.AuthCodeStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		s := defaultimpl.NewMemoryAuthCodeStore()
		s.MaxEntries = cfg.AuthCode.MaxEntries
		if cfg.AuthCode.ReapInterval > 0 {
			s.StartReaper(cfg.AuthCode.ReapInterval)
		}
		return s, nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		keys, err := ResolveOAuthLookupHMACKeys(cfg.SQLite)
		if err != nil {
			return nil, err
		}
		store, err := sqlitestores.NewAuthCodeStore(cfg.SQLite.DSN)
		if err == nil {
			store.SetLookupHMACKeys(keys...)
			store.StartReaper(cfg.AuthCode.ReapInterval)
		}
		return store, err
	case "redis":
		if rdb == nil {
			return nil, errRedisNotConfigured("oauth")
		}
		store := redisbackend.NewAuthCodeStore(rdb)
		if err := configureRedisLookup(store, cfg.Redis); err != nil {
			return nil, err
		}
		return store, nil
	case "postgres":
		if pgDB == nil {
			return nil, errPostgresNotConfigured("oauth")
		}
		return buildPostgresAuthCodeStore(cfg, pgDB, pgDialect)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q (supported: memory, sqlite, redis, postgres)", cfg.Backend)
	}
}

func BuildRefreshTokenStore(cfg config.OAuthConfig, rdb goredis.Cmdable, pgDB *sql.DB, pgDialect postgresbackend.Dialect) (oauth.RefreshTokenStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		s := defaultimpl.NewMemoryRefreshTokenStore()
		s.MaxRotationsPerWindow = cfg.RefreshToken.MaxRotationsPerWindow
		s.RotationWindow = cfg.RefreshToken.RotationWindow
		s.MaxEntries = cfg.RefreshToken.MaxEntries
		if cfg.RefreshToken.ReapInterval > 0 {
			s.StartReaper(cfg.RefreshToken.ReapInterval)
		}
		return s, nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		return buildSQLiteRefreshTokenStore(cfg)
	case "redis":
		if rdb == nil {
			return nil, errRedisNotConfigured("oauth")
		}
		// WithRotationCap restores the per-family velocity cap the memory +
		// sqlite peers honor (the redis peer dropped it before this wiring).
		store := redisbackend.NewRefreshTokenStore(rdb,
			redisbackend.WithRotationCap(cfg.RefreshToken.MaxRotationsPerWindow, cfg.RefreshToken.RotationWindow),
		)
		if err := configureRedisLookup(store, cfg.Redis); err != nil {
			return nil, err
		}
		return store, nil
	case "postgres":
		if pgDB == nil {
			return nil, errPostgresNotConfigured("oauth")
		}
		return buildPostgresRefreshTokenStore(cfg, pgDB, pgDialect)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q (supported: memory, sqlite, redis, postgres)", cfg.Backend)
	}
}

func BuildDeviceCodeStore(cfg config.OAuthConfig, rdb goredis.Cmdable, pgDB *sql.DB, pgDialect postgresbackend.Dialect) (oauth.DeviceCodeStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		s := defaultimpl.NewMemoryDeviceCodeStore()
		s.MaxEntries = cfg.DeviceCode.MaxEntries
		if cfg.DeviceCode.ReapInterval > 0 {
			s.StartReaper(cfg.DeviceCode.ReapInterval)
		}
		return s, nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		keys, err := ResolveOAuthLookupHMACKeys(cfg.SQLite)
		if err != nil {
			return nil, err
		}
		store, err := sqlitestores.NewDeviceCodeStore(cfg.SQLite.DSN)
		if err == nil {
			store.SetLookupHMACKeys(keys...)
			store.StartReaper(cfg.DeviceCode.ReapInterval)
		}
		return store, err
	case "redis":
		if rdb == nil {
			return nil, errRedisNotConfigured("oauth")
		}
		store := redisbackend.NewDeviceCodeStore(rdb)
		if err := configureRedisLookup(store, cfg.Redis); err != nil {
			return nil, err
		}
		return store, nil
	case "postgres":
		if pgDB == nil {
			return nil, errPostgresNotConfigured("oauth")
		}
		return buildPostgresDeviceCodeStore(cfg, pgDB, pgDialect)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q (supported: memory, sqlite, redis, postgres)", cfg.Backend)
	}
}

func BuildPARStore(cfg config.OAuthConfig, rdb goredis.Cmdable, pgDB *sql.DB, pgDialect postgresbackend.Dialect) (oauth.PARStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		s := defaultimpl.NewMemoryPARStore()
		s.MaxEntries = cfg.PAR.MaxEntries
		if cfg.PAR.ReapInterval > 0 {
			s.StartReaper(cfg.PAR.ReapInterval)
		}
		return s, nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		keys, err := ResolveOAuthLookupHMACKeys(cfg.SQLite)
		if err != nil {
			return nil, err
		}
		store, err := sqlitestores.NewPARStore(cfg.SQLite.DSN)
		if err == nil {
			store.SetLookupHMACKeys(keys...)
			store.StartReaper(cfg.PAR.ReapInterval)
		}
		return store, err
	case "redis":
		if rdb == nil {
			return nil, errRedisNotConfigured("oauth")
		}
		store := redisbackend.NewPARStore(rdb)
		if err := configureRedisLookup(store, cfg.Redis); err != nil {
			return nil, err
		}
		return store, nil
	case "postgres":
		if pgDB == nil {
			return nil, errPostgresNotConfigured("oauth")
		}
		return buildPostgresPARStore(cfg, pgDB, pgDialect)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q (supported: memory, sqlite, redis, postgres)", cfg.Backend)
	}
}

func buildPostgresAuthCodeStore(cfg config.OAuthConfig, db *sql.DB, dialect postgresbackend.Dialect) (oauth.AuthCodeStore, error) {
	store, err := postgresbackend.NewAuthCodeStoreWithDB(db, dialect)
	if err != nil {
		return nil, err
	}
	keys, err := ResolveOAuthPostgresLookupHMACKeys(cfg.Postgres)
	if err != nil {
		return nil, err
	}
	store.SetLookupHMACKeys(keys...)
	store.StartReaper(cfg.AuthCode.ReapInterval)
	return store, nil
}

func buildSQLiteRefreshTokenStore(cfg config.OAuthConfig) (oauth.RefreshTokenStore, error) {
	keys, err := ResolveOAuthLookupHMACKeys(cfg.SQLite)
	if err != nil {
		return nil, err
	}
	store, err := sqlitestores.NewRefreshTokenStore(cfg.SQLite.DSN)
	if err != nil {
		return nil, err
	}
	store.MaxRotationsPerWindow = cfg.RefreshToken.MaxRotationsPerWindow
	store.RotationWindow = cfg.RefreshToken.RotationWindow
	store.SetLookupHMACKeys(keys...)
	store.StartReaper(cfg.RefreshToken.ReapInterval)
	return store, nil
}

func buildPostgresRefreshTokenStore(cfg config.OAuthConfig, db *sql.DB, dialect postgresbackend.Dialect) (oauth.RefreshTokenStore, error) {
	store, err := postgresbackend.NewRefreshTokenStoreWithDB(db, dialect)
	if err != nil {
		return nil, err
	}
	store.MaxRotationsPerWindow = cfg.RefreshToken.MaxRotationsPerWindow
	store.RotationWindow = cfg.RefreshToken.RotationWindow
	keys, err := ResolveOAuthPostgresLookupHMACKeys(cfg.Postgres)
	if err != nil {
		return nil, err
	}
	store.SetLookupHMACKeys(keys...)
	store.StartReaper(cfg.RefreshToken.ReapInterval)
	return store, nil
}

func buildPostgresDeviceCodeStore(cfg config.OAuthConfig, db *sql.DB, dialect postgresbackend.Dialect) (oauth.DeviceCodeStore, error) {
	store, err := postgresbackend.NewDeviceCodeStoreWithDB(db, dialect)
	if err != nil {
		return nil, err
	}
	keys, err := ResolveOAuthPostgresLookupHMACKeys(cfg.Postgres)
	if err != nil {
		return nil, err
	}
	store.SetLookupHMACKeys(keys...)
	store.StartReaper(cfg.DeviceCode.ReapInterval)
	return store, nil
}

func buildPostgresPARStore(cfg config.OAuthConfig, db *sql.DB, dialect postgresbackend.Dialect) (oauth.PARStore, error) {
	store, err := postgresbackend.NewPARStoreWithDB(db, dialect)
	if err != nil {
		return nil, err
	}
	keys, err := ResolveOAuthPostgresLookupHMACKeys(cfg.Postgres)
	if err != nil {
		return nil, err
	}
	store.SetLookupHMACKeys(keys...)
	store.StartReaper(cfg.PAR.ReapInterval)
	return store, nil
}

// ResolveOAuthLookupHMACKeys loads the current and optional previous lookup
// keys. The current key writes new rows; both keys plus legacy plaintext are
// tried on reads, allowing a no-logout rolling rotation.
func ResolveOAuthLookupHMACKeys(cfg config.OAuthSQLiteConfig) ([][]byte, error) {
	return resolveOAuthLookupHMACKeys(
		cfg.LookupHMACKeyFile, cfg.LookupHMACPreviousKeyFile, "oauth.sqlite",
	)
}

// ResolveOAuthRedisLookupHMACKeys applies the same rotation contract to Redis.
func ResolveOAuthRedisLookupHMACKeys(cfg config.OAuthRedisConfig) ([][]byte, error) {
	return resolveOAuthLookupHMACKeys(
		cfg.LookupHMACKeyFile, cfg.LookupHMACPreviousKeyFile, "oauth.redis",
	)
}

// ResolveOAuthPostgresLookupHMACKeys applies the same rotation contract to
// the postgres backend's oauth.postgres lookup-key section.
func ResolveOAuthPostgresLookupHMACKeys(cfg config.OAuthPostgresConfig) ([][]byte, error) {
	return resolveOAuthLookupHMACKeys(
		cfg.LookupHMACKeyFile, cfg.LookupHMACPreviousKeyFile, "oauth.postgres",
	)
}

type lookupHMACStore interface {
	SetLookupHMACKeys(...[]byte)
}

func configureRedisLookup(store lookupHMACStore, cfg config.OAuthRedisConfig) error {
	keys, err := ResolveOAuthRedisLookupHMACKeys(cfg)
	if err == nil {
		store.SetLookupHMACKeys(keys...)
	}
	return err
}

func resolveOAuthLookupHMACKeys(currentFile, previousFile, scope string) ([][]byte, error) {
	if currentFile == "" {
		if previousFile != "" {
			return nil, fmt.Errorf("%s.lookup_hmac_previous_key_file requires lookup_hmac_key_file", scope)
		}
		return nil, nil
	}
	current, err := readOAuthLookupHMACKey(currentFile)
	if err != nil {
		return nil, fmt.Errorf("%s lookup HMAC current key: %w", scope, err)
	}
	keys := [][]byte{current}
	if previousFile != "" {
		previous, err := readOAuthLookupHMACKey(previousFile)
		if err != nil {
			return nil, fmt.Errorf("%s lookup HMAC previous key: %w", scope, err)
		}
		keys = append(keys, previous)
	}
	return keys, nil
}

func readOAuthLookupHMACKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		key = []byte(strings.TrimRight(string(key), "\r\n"))
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("key file %q must contain at least 32 bytes", path)
	}
	return key, nil
}

// ResolvePairwiseSalt reads the pairwise hash salt with the same
// file-wins-over-inline precedence the PII redactor uses. Empty
// salt falls back to security.DefaultPairwiseSalt — fine for tests, not
// fine for production (publicly known).
func ResolvePairwiseSalt(cfg config.PairwiseSubjectsConfig) (string, error) {
	if cfg.SaltFile != "" {
		b, err := os.ReadFile(cfg.SaltFile)
		if err != nil {
			return "", fmt.Errorf("read salt file: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return cfg.Salt, nil
}

// ResolvePIISalt reads the redaction salt from inline YAML or a file
// (file wins when both set — operators typically use file for prod).
// Returns an error when both are empty so a misconfiguration becomes
// loud at boot rather than silently degrading to an empty salt that
// makes hash inversion trivial.
func ResolvePIISalt(cfg config.AuditPIIRedactionConfig) (string, error) {
	if cfg.SaltFile != "" {
		b, err := os.ReadFile(cfg.SaltFile)
		if err != nil {
			return "", fmt.Errorf("read salt file: %w", err)
		}
		s := strings.TrimRight(string(b), "\r\n")
		if s == "" {
			return "", fmt.Errorf("salt file %q is empty", cfg.SaltFile)
		}
		return s, nil
	}
	if cfg.Salt == "" {
		return "", errors.New("salt or salt_file must be set when pii_redaction is enabled")
	}
	return cfg.Salt, nil
}
