package serverbuildstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/infrastructure/defaultimpl"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/snapshot"

	encryptionaes "github.com/snaplink/sso/interfaces/snapshot/encryptionaesgcm"

	encryptionnone "github.com/snaplink/sso/interfaces/snapshot/encryptionnone"

	encryptionpass "github.com/snaplink/sso/interfaces/snapshot/encryptionpassphrase"

	storagefile "github.com/snaplink/sso/interfaces/snapshot/storagefile"

	"github.com/snaplink/sso/domains/tenant"
	storageinline "github.com/snaplink/sso/interfaces/snapshot/storageinline"

	tenantmemory "github.com/snaplink/sso/domains/tenant/memory"

	tenantsqlite "github.com/snaplink/sso/domains/tenant/sqlite"
)

// buildMFAChallengeStore selects the MFA challenge store backend (memory for
// single-replica, sqlite for clusters). Same backend-selection pattern
// security.AccountLockout / security.SubjectClientIndex use; the schema gets
// migrated at construction so no separate boot step is required. The returned
// string is the operator-facing backend label for the startup log.
func buildMFAChallengeStore(cfg config.MFAChallengeConfig) (spi.MFAChallengeStore, string, error) {
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
	default:
		return nil, "", fmt.Errorf("unknown mfa.challenge.backend %q (supported: memory, sqlite)", cfg.Backend)
	}
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
func buildTenantStoreBackend(cfg config.TenantConfig, logger spi.Logger) (tenant.Store, error) {
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
	default:
		return nil, fmt.Errorf("unknown tenant.backend %q (supported: memory, sqlite)", cfg.Backend)
	}
}

// seedTenantStore writes the declared tenants + domains into store. The caller
// owns store.Close on error (the partial seed is discarded with the store).
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
