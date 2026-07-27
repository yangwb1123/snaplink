package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/platform/bootstrap"
	"github.com/yangwb1123/snaplink/platform/bootstrap/builtin"
	"github.com/yangwb1123/snaplink/shared/spi"

	bootstrapfile "github.com/yangwb1123/snaplink/platform/bootstrap/file"
	"github.com/yangwb1123/snaplink/platform/bootstrap/lock"

	lockEtcd "github.com/yangwb1123/snaplink/platform/bootstrap/locketcd"

	lockFile "github.com/yangwb1123/snaplink/platform/bootstrap/lockfile"

	"github.com/yangwb1123/snaplink/config"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	lockNoop "github.com/yangwb1123/snaplink/platform/bootstrap/locknoop"
)

func runBootstrap(cfg *config.Config, a *app, logger spi.Logger) error {
	statePath := cfg.Bootstrap.StatePath
	if statePath == "" {
		statePath = "bootstrap.json"
	}
	tracker, err := bootstrapfile.New(statePath)
	if err != nil {
		return fmt.Errorf("tracker: %w", err)
	}
	defer func() { _ = tracker.Close() }()

	seed := buildAdminSeed(cfg, a, logger)

	// Snapshot restore runs BEFORE the runner so AdvanceBootstrap can
	// bump the Tracker — that lets seed steps already covered by the
	// snapshot skip themselves on the same boot. Restorer.Tracker must
	// be wired here because the tracker isn't constructed until now.
	if err := applyBootstrapSnapshotRestore(cfg, a, tracker, logger); err != nil {
		return err
	}

	bootLock, lockCloser, err := buildBootstrapLock(cfg, logger)
	if err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	if lockCloser != nil {
		defer lockCloser()
	}

	opts := bootstrapRunnerOptions(cfg, a, bootLock, logger)
	runner := bootstrap.NewRunner(bootstrapNamespace, tracker, opts...)
	runner.Register(builtin.Steps(seed)...)
	logger.Info("bootstrap: applying pending steps", "namespace", bootstrapNamespace, "state_file", statePath)
	return runner.Run(context.Background())
}

// buildAdminSeed assembles the AdminSeed bundle. When an admin_password_file is
// configured, the printer additionally writes the one-shot password to disk at
// 0600 (atomic tmp+rename) alongside the stdout banner.
func buildAdminSeed(cfg *config.Config, a *app, logger spi.Logger) *builtin.AdminSeed {
	seed := &builtin.AdminSeed{
		Permissions:    a.provider,
		Users:          a.userProvider,
		Clients:        a.clientStore,
		Netpolicy:      a.netStore,
		AdminUserID:    cfg.Bootstrap.AdminUserID,
		AdminClientID:  cfg.Bootstrap.AdminClientID,
		AdminRoleCode:  cfg.Bootstrap.AdminRoleCode,
		AdminClientApp: cfg.Bootstrap.AdminClientApp,
	}
	path := cfg.Bootstrap.AdminPasswordFile
	if path == "" {
		return seed
	}
	// Compose stdout printer (banner stays so live operators
	// still see the value) + file write at 0600. Atomic write
	// via tmp+rename so a crashed write doesn't leave an empty
	// file the operator trusts.
	baseStdout := func(p string) {
		fmt.Printf("\n=========================================================\n")
		fmt.Printf(" SSO admin user seeded — capture this password NOW. It is\n")
		fmt.Printf(" printed once and never again.\n")
		fmt.Printf("   user_id: %s\n   password: %s\n   file:     %s (mode 0600)\n", cfg.Bootstrap.AdminUserID, p, path)
		fmt.Printf("=========================================================\n\n")
	}
	seed.PasswordPrinter = func(p string) {
		if err := writeAdminPasswordFile(path, p); err != nil {
			logger.Error("bootstrap: write admin password file failed", "error", err, "path", path)
		}
		baseStdout(p)
	}
	return seed
}

// applyBootstrapSnapshotRestore runs the configured snapshot restore (if any)
// and wires the Restorer's Tracker. No-op when snapshot restore is not
// configured.
func applyBootstrapSnapshotRestore(cfg *config.Config, a *app, tracker *bootstrapfile.Tracker, logger spi.Logger) error {
	if !cfg.Snapshot.Enabled || cfg.Snapshot.RestoreFrom == "" || a.snapshotPipeline == nil || a.snapshotRestorer == nil {
		return nil
	}
	a.snapshotRestorer.Tracker = tracker
	plan := &builtin.RestorePlan{
		URI:      cfg.Snapshot.RestoreFrom,
		Pipeline: a.snapshotPipeline,
		Restorer: a.snapshotRestorer,
	}
	logger.Info("bootstrap: applying snapshot restore", "uri", cfg.Snapshot.RestoreFrom)
	rep, err := builtin.ApplyRestore(context.Background(), plan)
	if err != nil {
		return fmt.Errorf("snapshot restore: %w", err)
	}
	if rep != nil {
		logger.Info("bootstrap: snapshot restored",
			"mode", rep.Mode,
			"bootstrap_advanced_to", rep.Bootstrap.To,
			"items", len(rep.Items))
	}
	return nil
}

// bootstrapRunnerOptions builds the Runner options, attaching the distributed
// lock (key/TTL/blocking) when one was configured.
func bootstrapRunnerOptions(cfg *config.Config, a *app, bootLock lock.Lock, logger spi.Logger) []bootstrap.Option {
	opts := []bootstrap.Option{
		bootstrap.WithRecorder(a.recorder),
		bootstrap.WithLogger(serverbuildstore.BootstrapLogger{Inner: logger}),
	}
	if bootLock == nil {
		return opts
	}
	key := cfg.Bootstrap.Lock.Key
	if key == "" {
		key = "/sso/bootstrap/" + bootstrapNamespace
	}
	opts = append(opts, bootstrap.WithLock(bootLock, key))
	if cfg.Bootstrap.Lock.TTL > 0 {
		opts = append(opts, bootstrap.WithLockTTL(cfg.Bootstrap.Lock.TTL))
	}
	if cfg.Bootstrap.Lock.Blocking {
		opts = append(opts, bootstrap.WithLockBlocking(true, cfg.Bootstrap.Lock.Backoff))
	}
	return opts
}

// buildBootstrapLock translates BootstrapLockConfig into a concrete
// lock.Lock implementation. Returns (nil, nil, nil) when no
// coordination is requested — Runner falls back to single-replica path.
// The closer (when non-nil) MUST be called after the Runner exits to
// release the etcd client / file handles.
func buildBootstrapLock(cfg *config.Config, logger spi.Logger) (lock.Lock, func(), error) {
	switch strings.ToLower(cfg.Bootstrap.Lock.Backend) {
	case "", "noop":
		return nil, nil, nil
	case "file":
		dir := cfg.Bootstrap.Lock.File.Dir
		logger.Info("bootstrap lock: file backend", "dir", dir)
		return lockFile.New(dir), nil, nil
	case "etcd":
		ec := cfg.Bootstrap.Lock.Etcd
		if len(ec.Endpoints) == 0 {
			return nil, nil, fmt.Errorf("bootstrap.lock.etcd.endpoints required when backend=etcd")
		}
		l, err := lockEtcd.New(lockEtcd.Config{
			Endpoints:   ec.Endpoints,
			DialTimeout: ec.DialTimeout,
			Username:    ec.Username,
			Password:    ec.Password,
		})
		if err != nil {
			return nil, nil, err
		}
		logger.Info("bootstrap lock: etcd backend", "endpoints", ec.Endpoints)
		return l, func() { _ = l.Close() }, nil
	default:
		return nil, nil, fmt.Errorf("unknown bootstrap.lock.backend %q", cfg.Bootstrap.Lock.Backend)
	}
}

// _ keeps the noop import live for documentation purposes; we don't
// instantiate it explicitly because nil-Lock has the same effect.
var _ = lockNoop.New

// wireRedis builds the ONE shared Redis client when a redis block is declared,
// stashing it on the builder so every store with backend:redis fans out from it
// (one connection pool per replica, not one per store). Called first in buildApp
// so all later wireXxx can consume it. No redis block => b.redis stays nil and
// the memory/sqlite paths are byte-identical.
//
// Lives here (not build_stores.go, which is at its 500-line budget) alongside
// wirePostgres — both are shared-datastore-connection setup, the same
// composition-time concern as the bootstrap wiring above, and
// cmd/sso-server is at its frozen file-count ceiling (directory_fanout_test.go),
// so a new sibling file isn't an option.
func (b *appBuilder) wireRedis() error {
	rc := b.cfg.Redis
	if !rc.Configured() {
		return nil
	}
	opts, err := redisOptionsFromConfig(rc)
	if err != nil {
		return err
	}
	client, err := redisbackend.NewUniversalClient(opts)
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	b.redis = client
	// Drain the replica from the LB when its Redis is unreachable, but bound the
	// ping so a brief failover blip doesn't hang /readyz (the cluster client
	// re-resolves MOVED/ASK). /livez stays always-200 so kubelet does not
	// kill-restart the fleet during a shared-store blip.
	rdb := client
	b.opts = append(b.opts, sso.WithReadyCheck("redis", func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return rdb.Ping(ctx).Err()
	}))
	mode := rc.Mode
	if mode == "" {
		mode = "auto"
	}
	b.logger.Info("redis: shared client configured (HA hot-path backend)",
		"mode", mode, "addr_count", len(rc.Addrs))
	return nil
}

// redisOptionsFromConfig maps the config block onto the redis module's Options,
// resolving password_file. Kept separate so wireRedis stays within the function
// budget.
func redisOptionsFromConfig(rc config.RedisConfig) (redisbackend.Options, error) {
	password := rc.Password
	if password == "" && rc.PasswordFile != "" {
		raw, err := os.ReadFile(rc.PasswordFile)
		if err != nil {
			return redisbackend.Options{}, fmt.Errorf("redis: read password_file: %w", err)
		}
		password = strings.TrimRight(string(raw), "\r\n")
	}
	return redisbackend.Options{
		Mode:            rc.Mode,
		Addrs:           rc.Addrs,
		Username:        rc.Username,
		Password:        password,
		DB:              rc.DB,
		MasterName:      rc.MasterName,
		PoolSize:        rc.PoolSize,
		MinIdleConns:    rc.MinIdleConns,
		MaxRetries:      rc.MaxRetries,
		DialTimeout:     rc.DialTimeout,
		ReadTimeout:     rc.ReadTimeout,
		WriteTimeout:    rc.WriteTimeout,
		PoolTimeout:     rc.PoolTimeout,
		ConnMaxIdleTime: rc.ConnMaxIdleTime,
		ConnMaxLifetime: rc.ConnMaxLifetime,
		RouteByLatency:  rc.RouteByLatency,
		RouteRandomly:   rc.RouteRandomly,
		ReadOnly:        rc.ReadOnly,
		TLS:             redisTLSOptions(rc.TLS),
	}, nil
}

// redisTLSOptions maps the config TLS block onto the redis module's options,
// returning nil (plaintext) when TLS is off.
func redisTLSOptions(t config.RedisTLSConfig) *redisbackend.TLSOptions {
	if !t.Enabled {
		return nil
	}
	return &redisbackend.TLSOptions{
		Enabled:            true,
		CAFile:             t.CAFile,
		CertFile:           t.CertFile,
		KeyFile:            t.KeyFile,
		ServerName:         t.ServerName,
		InsecureSkipVerify: t.InsecureSkipVerify,
	}
}

// wirePostgres builds the ONE shared Postgres-wire *sql.DB pool when a postgres
// block is declared, so every DURABLE store with backend:postgres fans out from
// it (one pool per replica, not one per store). No postgres block => b.pgDB
// stays nil and the memory/sqlite paths are byte-identical.
func (b *appBuilder) wirePostgres() error {
	pc := b.cfg.Postgres
	if !pc.Configured() {
		return nil
	}
	dialect := postgresbackend.Dialect(pc.Dialect)
	db, err := postgresbackend.Open(postgresbackend.Config{
		DSN:             pc.DSN,
		Dialect:         dialect,
		MaxOpenConns:    pc.MaxOpenConns,
		MaxIdleConns:    pc.MaxIdleConns,
		ConnMaxLifetime: pc.ConnMaxLifetime,
		ConnMaxIdleTime: pc.ConnMaxIdleTime,
	})
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	b.pgDB = db
	b.pgDialect = dialect
	// Drain the replica from the LB when the durable store is unreachable, with
	// a bounded ping so a brief blip doesn't hang /readyz. /livez stays
	// always-200 so kubelet doesn't kill-restart the fleet during a DB blip.
	pg := db
	b.opts = append(b.opts, sso.WithReadyCheck("postgres", func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return pg.PingContext(ctx)
	}))
	d := pc.Dialect
	if d == "" {
		d = "postgres"
	}
	b.logger.Info("postgres: shared durable pool configured (HA db-cluster backend)", "dialect", d)
	return nil
}

// serverbuildstore.BuildDPoPNonceProvider materializes the RFC 9449 §8 nonce
// provider from config. When KeyFile is set, the file's contents
// (raw bytes or hex-encoded — both shapes are accepted, hex first)
// seed the HMAC. Without a file, a process-local 32-byte secret is
// generated — fine for single-replica or dev, but DOES break nonce
// continuity across replicas, so multi-replica deployments MUST
// supply a key file.
// serverbuildauthn.BuildPairwiseSubjectStore picks the pairwise reverse-lookup
// backend. memory keeps the single-replica story; sqlite shares
// (pairwise → local) so /userinfo + revoke + end_session on any
// replica can resolve any in-flight bearer token.
