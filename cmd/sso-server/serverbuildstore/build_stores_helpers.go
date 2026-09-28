package serverbuildstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"

	"github.com/yangwb1123/snaplink/shared/spi"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"

	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"

	encryptionaes "github.com/yangwb1123/snaplink/interfaces/snapshot/encryptionaesgcm"

	encryptionnone "github.com/yangwb1123/snaplink/interfaces/snapshot/encryptionnone"

	encryptionpass "github.com/yangwb1123/snaplink/interfaces/snapshot/encryptionpassphrase"

	storagefile "github.com/yangwb1123/snaplink/interfaces/snapshot/storagefile"

	"github.com/yangwb1123/snaplink/domains/tenant"
	storageinline "github.com/yangwb1123/snaplink/interfaces/snapshot/storageinline"

	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"

	tenantsqlite "github.com/yangwb1123/snaplink/domains/tenant/sqlite"
)

// buildMFAChallengeStore selects the MFA challenge store backend (memory for
// single-replica, sqlite for clusters). Same backend-selection pattern
// security.AccountLockout / security.SubjectClientIndex use; the schema gets
// migrated at construction so no separate boot step is required. The returned
// string is the operator-facing backend label for the startup log.
func buildMFAChallengeStore(cfg config.MFAChallengeConfig, rdb goredis.Cmdable) (spi.MFAChallengeStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return defaultimpl.NewMemoryMFAChallengeStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("mfa.challenge.sqlite.dsn required when backend=sqlite")
		}
		s, err := sqlitestores.NewMFAChallengeStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return s, "sqlite (cluster-shared)", nil
	case "redis":
		if rdb == nil {
			return nil, "", errRedisNotConfigured("mfa.challenge")
		}
		return redisbackend.NewMFAChallengeStore(rdb), "redis (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown mfa.challenge.backend %q (supported: memory, sqlite, redis)", cfg.Backend)
	}
}

// BuildLoginTransactionStore selects the one-use store used to bridge an
// upstream federation callback back into hosted login. It intentionally shares
// the MFA challenge backend configuration so deployments do not need a second
// persistence knob for the same atomic consume contract.
func BuildLoginTransactionStore(cfg config.MFAChallengeConfig, rdb goredis.Cmdable) (spi.MFAChallengeStore, string, error) {
	return buildMFAChallengeStore(cfg, rdb)
}

// buildPushApprovalStore selects the push-approval store backend (memory for
// single-replica, sqlite for cluster). Returns the store plus the concrete
// sqlite handle (nil for memory) so cmd can register a /readyz check + launch
// the PruneExpired loop against it.
func buildPushApprovalStore(cfg config.MFAPushConfig) (defaultimpl.PushApprovalStore, *sqlitestores.PushApprovalStore, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return defaultimpl.NewMemoryPushApprovalStore(), nil, nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, nil, errors.New("mfa.provider.push.sqlite.dsn required when backend=sqlite")
		}
		s, err := sqlitestores.NewPushApprovalStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, nil, fmt.Errorf("mfa.provider.push.sqlite: %w", err)
		}
		return s, s, nil
	default:
		return nil, nil, fmt.Errorf("unknown mfa.provider.push.backend %q (supported: memory, sqlite)", cfg.Backend)
	}
}

// buildPushTransport selects the push delivery transport: log (default; writes
// to log) or webhook (POSTs to operator-supplied URL via
// HTTPWebhookPushTransport). Custom transports (FCM/APNs SDK) ship via SDK fork.
func buildPushTransport(cfg config.MFAPushConfig, logger spi.Logger) (defaultimpl.PushTransport, error) {
	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if transport == "" {
		transport = "log"
	}
	switch transport {
	case "log":
		return defaultimpl.PushTransportFunc(func(_ context.Context, id, subject string, _ map[string]string) error {
			logger.Info("push approval delivered (log-only transport — set transport=webhook for real push)",
				"approval_id", id, "subject", subject)
			return nil
		}), nil
	case "webhook":
		return BuildPushWebhookTransport(cfg.Webhook)
	default:
		return nil, fmt.Errorf("unknown mfa.provider.push.transport %q (supported: log, webhook)", transport)
	}
}

// pushMFAOptions translates the optional push tuning knobs into SDK options.
func pushMFAOptions(cfg config.MFAPushConfig) []defaultimpl.PushMFAOption {
	var opts []defaultimpl.PushMFAOption
	if cfg.PollInterval > 0 {
		opts = append(opts, defaultimpl.WithPushPollInterval(cfg.PollInterval))
	}
	if cfg.MaxWait > 0 {
		opts = append(opts, defaultimpl.WithPushMaxWait(cfg.MaxWait))
	}
	if cfg.ChannelNotify {
		opts = append(opts, defaultimpl.WithPushChannelNotify())
	}
	return opts
}

// buildSnapshotStorage selects the snapshot Storage backend (file on disk or
// inline in-memory). file defaults the directory to ./snapshots.
func buildSnapshotStorage(cfg config.SnapshotStorageConfig, logger spi.Logger) (snapshot.Storage, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "file":
		dir := cfg.File.Dir
		if dir == "" {
			dir = "./snapshots"
		}
		s, err := storagefile.New(dir)
		if err != nil {
			return nil, fmt.Errorf("snapshot file storage: %w", err)
		}
		logger.Info("snapshot storage: file", "dir", dir)
		return s, nil
	case "inline":
		logger.Info("snapshot storage: inline (in-memory)")
		return storageinline.New(), nil
	default:
		return nil, fmt.Errorf("unknown snapshot.storage.backend %q", cfg.Backend)
	}
}

// buildSnapshotSealer selects the snapshot Sealer (none, passphrase, or
// aes-gcm). passphrase reads its secret inline or from a file; aes-gcm resolves
// the 32-byte key via LoadAESGCMKey.
func buildSnapshotSealer(cfg config.SnapshotEncryptionConfig, logger spi.Logger) (snapshot.Sealer, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "none":
		return encryptionnone.New(), nil
	case "passphrase":
		pass := cfg.Passphrase
		if pass == "" && cfg.PassphraseFile != "" {
			b, err := os.ReadFile(cfg.PassphraseFile)
			if err != nil {
				return nil, fmt.Errorf("snapshot passphrase file: %w", err)
			}
			pass = strings.TrimRight(string(b), "\r\n")
		}
		if pass == "" {
			return nil, errors.New("snapshot.encryption.backend=passphrase requires passphrase or passphrase_file")
		}
		logger.Info("snapshot encryption: passphrase (argon2id+chacha20poly1305)")
		return encryptionpass.NewFromString(pass), nil
	case "aes-gcm", "aes-256-gcm":
		key, err := LoadAESGCMKey(cfg)
		if err != nil {
			return nil, err
		}
		s, err := encryptionaes.New(key)
		if err != nil {
			return nil, fmt.Errorf("snapshot aes-gcm: %w", err)
		}
		logger.Info("snapshot encryption: aes-256-gcm (direct key from KMS)")
		return s, nil
	default:
		return nil, fmt.Errorf("unknown snapshot.encryption.backend %q (supported: none, passphrase, aes-gcm)", cfg.Backend)
	}
}

// buildTenantStoreBackend selects the tenant.Store backend (memory in-process
// or sqlite cluster-shared).
func buildTenantStoreBackend(cfg config.TenantConfig, logger spi.Logger, pg *sql.DB, dialect postgresbackend.Dialect) (tenant.Store, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		logger.Info("tenant store: memory (in-process)")
		return tenantmemory.New(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("tenant.sqlite.dsn required when tenant.backend=sqlite")
		}
		s, err := tenantsqlite.New(cfg.SQLite.DSN)
		if err != nil {
			return nil, fmt.Errorf("tenant sqlite: %w", err)
		}
		logger.Info("tenant store: sqlite (cluster-shared)", "dsn", cfg.SQLite.DSN)
		return s, nil
	case "postgres":
		if pg == nil {
			return nil, errPostgresNotConfigured("tenant")
		}
		s, err := postgresbackend.NewTenantStoreWithDB(pg, dialect)
		if err != nil {
			return nil, fmt.Errorf("tenant postgres: %w", err)
		}
		logger.Info("tenant store: postgres (cluster-shared)")
		return s, nil
	default:
		return nil, fmt.Errorf("unknown tenant.backend %q (supported: memory, sqlite, postgres)", cfg.Backend)
	}
}

// BuildTenantMembershipStore selects the explicit B2B tenant-user roster store.
// An empty or disabled backend leaves the membership-dependent surfaces off.
func BuildTenantMembershipStore(cfg config.TenantMembershipConfig) (core.TenantUserStore, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "disabled":
		return nil, nil
	case "memory":
		return defaultimpl.NewMemoryTenantUserStore(), nil
	case "sqlite":
		if strings.TrimSpace(cfg.SQLite.DSN) == "" {
			return nil, errors.New("tenant.memberships.sqlite.dsn required when backend=sqlite")
		}
		store, err := sqlitestores.NewTenantUserStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, fmt.Errorf("tenant memberships sqlite: %w", err)
		}
		return store, nil
	default:
		return nil, fmt.Errorf("unknown tenant.memberships.backend %q (supported: memory, sqlite)", cfg.Backend)
	}
}

// TenantStoreWiring carries the options and health probe for the tenant domain.
type TenantStoreWiring struct {
	Options       []sso.Option
	HealthSources []sso.StorageHealthSource
}

// BuildTenantStoreWiring binds tenant resolution, health, and suspension policy.
func BuildTenantStoreWiring(cfg config.TenantConfig, store tenant.Store, logger spi.Logger) TenantStoreWiring {
	wiring := TenantStoreWiring{Options: []sso.Option{sso.WithTenantStore(store)}}
	if p, ok := store.(interface{ Ping(context.Context) error }); ok {
		wiring.Options = append(wiring.Options, sso.WithReadyCheck("sqlite-tenant", p.Ping))
		source := sso.StorageHealthSource{Name: "sqlite-tenant", Ping: p.Ping}
		if db, ok := store.(interface{ DB() *sql.DB }); ok && db.DB() != nil {
			database := db.DB()
			source.SchemaVersions = func(ctx context.Context) (map[string]int, error) {
				return sqliteSchemaVersions(ctx, database)
			}
		}
		wiring.HealthSources = append(wiring.HealthSources, source)
	}
	wiring.Options = append(wiring.Options, sso.WithTenantMiddlewareOptions(sso.TenantMiddlewareOptions{
		Timeout:          cfg.LookupTimeout,
		IncludeSuspended: cfg.IncludeSuspended,
		OnError: func(err error) {
			logger.Error("tenant resolution failed", "error", err)
		},
	}))
	if cfg.SuspensionCheck.Enabled {
		wiring.Options = append(wiring.Options, sso.WithTenantSuspensionCheck(cfg.SuspensionCheck.CacheTTL))
	}
	return wiring
}

// TenantMembershipWiring carries the roster store and its server health wiring.
type TenantMembershipWiring struct {
	Store         core.TenantUserStore
	Options       []sso.Option
	HealthSources []sso.StorageHealthSource
}

// BuildTenantMembershipWiring keeps the roster store, server options,
// readiness probe, and storage-health view bound to the same backend.
func BuildTenantMembershipWiring(ctx context.Context, cfg config.TenantMembershipConfig) (TenantMembershipWiring, error) {
	store, err := BuildTenantMembershipStore(cfg)
	if err != nil || store == nil {
		return TenantMembershipWiring{}, err
	}
	if db, ok := store.(interface{ DB() *sql.DB }); ok && db.DB() != nil {
		if err := migrate.CheckSchema(ctx, db.DB(), "tenant_memberships", sqlitestores.TenantMembershipsMaxVersion()); err != nil {
			if closer, ok := store.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
			return TenantMembershipWiring{}, fmt.Errorf("schema check tenant_memberships: %w", err)
		}
	}
	wiring := TenantMembershipWiring{Store: store, Options: []sso.Option{sso.WithTenantUserStore(store)}}
	if p, ok := store.(interface{ Ping(context.Context) error }); ok {
		wiring.Options = append(wiring.Options, sso.WithReadyCheck("tenant-memberships", p.Ping))
		source := sso.StorageHealthSource{Name: "tenant-memberships", Ping: p.Ping}
		if db, ok := store.(interface{ DB() *sql.DB }); ok && db.DB() != nil {
			database := db.DB()
			source.SchemaVersions = func(ctx context.Context) (map[string]int, error) {
				return sqliteSchemaVersions(ctx, database)
			}
		}
		wiring.HealthSources = append(wiring.HealthSources, source)
	}
	return wiring, nil
}

func sqliteSchemaVersions(ctx context.Context, db *sql.DB) (map[string]int, error) {
	statuses, err := migrate.Status(ctx, db)
	if err != nil {
		return nil, err
	}
	versions := make(map[string]int, len(statuses))
	for _, status := range statuses {
		versions[status.Namespace] = status.Version
	}
	return versions, nil
}

// BuildTenantTokenStrategyOptions validates each tenant-pinned token strategy
// and returns the matching server options before any request is served.
func BuildTenantTokenStrategyOptions(tenants []config.TenantSeedConfig, logger spi.Logger) ([]sso.Option, error) {
	var options []sso.Option
	for _, tn := range tenants {
		if tn.TokenStrategy == "" {
			continue
		}
		if tn.TokenStrategy != sso.TokenStrategyJWT && tn.TokenStrategy != sso.TokenStrategySession {
			return nil, fmt.Errorf("tenant %q token_strategy %q is not a registered strategy (want %q or %q)",
				tn.ID, tn.TokenStrategy, sso.TokenStrategyJWT, sso.TokenStrategySession)
		}
		options = append(options, sso.WithTenantTokenIssuer(tn.ID, tn.TokenStrategy))
		logger.Info("tenant token strategy bound", "tenant", tn.ID, "strategy", tn.TokenStrategy)
	}
	return options, nil
}

// BuildTenantUsageOptions keeps the usage endpoint absent when metering is off.
func BuildTenantUsageOptions(cfg config.TenantUsageMeteringConfig, logger spi.Logger) ([]sso.Option, error) {
	aggregator, err := BuildTenantUsageAggregator(cfg)
	if err != nil {
		return nil, err
	}
	if aggregator == nil {
		return nil, nil
	}
	logger.Info("tenant usage metering enabled", "backend", cfg.Backend)
	return []sso.Option{sso.WithTenantUsageAggregator(aggregator)}, nil
}

// seedTenantStore writes declared tenants + domains. The caller owns Close on error.
func seedTenantStore(store tenant.Store, cfg config.TenantConfig) error {
	ctx := context.Background()
	for _, t := range cfg.Tenants {
		status := tenant.Status(t.Status)
		if status == "" {
			status = tenant.StatusActive
		}
		if err := store.PutTenant(ctx, &tenant.Tenant{
			ID:       t.ID,
			Slug:     t.Slug,
			Name:     t.Name,
			Status:   status,
			Settings: t.Settings,
		}); err != nil {
			return fmt.Errorf("seed tenant %q: %w", t.ID, err)
		}
	}
	for _, d := range cfg.Domains {
		if err := store.PutDomain(ctx, &tenant.Domain{
			Hostname:        d.Hostname,
			TenantID:        d.TenantID,
			DefaultClientID: d.DefaultClientID,
			IsApex:          d.IsApex,
			Branding:        d.Branding,
		}); err != nil {
			return fmt.Errorf("seed domain %q: %w", d.Hostname, err)
		}
	}
	return nil
}
