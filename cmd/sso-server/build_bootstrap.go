package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/snaplink/sso/platform/bootstrap"
	"github.com/snaplink/sso/platform/bootstrap/builtin"
	"github.com/snaplink/sso/shared/spi"

	bootstrapfile "github.com/snaplink/sso/platform/bootstrap/file"
	"github.com/snaplink/sso/platform/bootstrap/lock"

	lockEtcd "github.com/snaplink/sso/platform/bootstrap/locketcd"

	lockFile "github.com/snaplink/sso/platform/bootstrap/lockfile"

	"github.com/snaplink/sso/config"
	lockNoop "github.com/snaplink/sso/platform/bootstrap/locknoop"
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
	if !(cfg.Snapshot.Enabled && cfg.Snapshot.RestoreFrom != "" && a.snapshotPipeline != nil && a.snapshotRestorer != nil) {
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
		bootstrap.WithLogger(bootstrapLogger{inner: logger}),
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

// buildDPoPNonceProvider materializes the RFC 9449 §8 nonce
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
