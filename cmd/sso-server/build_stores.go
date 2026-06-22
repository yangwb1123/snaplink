package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/spi"

	postgresbackend "github.com/snaplink/sso/postgres"
	redisbackend "github.com/snaplink/sso/redis"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/interfaces/sso"
)

// buildApp is pure server-assembly wiring: it reads config and constructs the
// Server with every WithXxx option, store, subsystem, and background worker.
// The work is delegated to ordered wireXxx sub-builders on appBuilder (defined
// across build_app*.go), grouped into three phases (foundation -> domains ->
// edge) whose Option-application order is identical to the original monolith
// (option order can decide which security feature wins), as is every
// conditional, error-wrap, defer/cleanup, and background-worker handoff.
func buildApp(cfg *config.Config, logger spi.Logger) (builtApp *app, retErr error) {
	b := &appBuilder{cfg: cfg, logger: logger}
	// The shared Redis client + Postgres pool must exist before any store
	// builder runs, since stores may select backend:redis (hot) or
	// backend:postgres (durable).
	if err := b.wireRedis(); err != nil {
		return nil, err
	}
	if err := b.wirePostgres(); err != nil {
		return nil, err
	}
	if err := b.wireFoundation(); err != nil {
		return nil, err
	}
	// If buildApp fails downstream, stop the classifier's watch loop so its
	// goroutine + context don't leak; on success the app owns netCancel and
	// calls it at shutdown. Registered here (after wireFoundation populates
	// netCancel, before the later phases) so the LIFO cleanup fires for any
	// later error, exactly as the original defer did.
	if b.netCancel != nil {
		defer func() {
			if retErr != nil {
				b.netCancel()
			}
		}()
	}
	if err := b.wireDomains(); err != nil {
		return nil, err
	}
	if err := b.wireEdge(); err != nil {
		return nil, err
	}
	return b.finalize()
}

// wireFoundation runs the kernel sub-builders (identity/signing, audit,
// permissions, network) that the later phases depend on. wireNetwork populates
// b.netCancel, so buildApp registers the on-failure cancel defer immediately
// after this phase returns.
func (b *appBuilder) wireFoundation() error {
	if err := b.wireIdentitySigning(); err != nil {
		return err
	}
	if err := b.wireAudit(); err != nil {
		return err
	}
	if err := b.wirePermissions(); err != nil {
		return err
	}
	return b.wireNetwork()
}

// wireDomains runs the business-domain sub-builders, in the same order the
// original monolith applied their Options.
func (b *appBuilder) wireDomains() error {
	if err := b.wireSelfServicePassword(); err != nil {
		return err
	}
	if err := b.wireGeoRegionRisk(); err != nil {
		return err
	}
	if err := b.wireWebAuthnMFA(); err != nil {
		return err
	}
	if err := b.wireAnomaly(); err != nil {
		return err
	}
	if err := b.wireTenant(); err != nil {
		return err
	}
	if err := b.wireConnectionsAndCache(); err != nil {
		return err
	}
	if err := b.wireDPoP(); err != nil {
		return err
	}
	return b.wireOAuthGrantStores()
}

// wireEdge runs the delivery-edge sub-builders (response encryption, DCR/
// backchannel, CAEP transmitter, federation, profiles/metadata, metrics, body/
// rate-limit, JTI-replay/SPIFFE, CAEP receiver/mesh, mTLS/lockout/proxies/CORS),
// in the original Option-application order. wireCAEPTransmitter and
// wireMetricsCollector return no error and keep their original positions.
func (b *appBuilder) wireEdge() error {
	if err := b.wireResponseEncryption(); err != nil {
		return err
	}
	if err := b.wireDCRBackchannel(); err != nil {
		return err
	}
	b.wireCAEPTransmitter()
	if err := b.wireFederation(); err != nil {
		return err
	}
	if err := b.wireProfilesAndMetadata(); err != nil {
		return err
	}
	b.wireMetricsCollector()
	if err := b.wireBodyAndRateLimit(); err != nil {
		return err
	}
	if err := b.wireJTIReplaySPIFFE(); err != nil {
		return err
	}
	if err := b.wireCAEPReceiverMesh(); err != nil {
		return err
	}
	return b.wireMTLSLockoutProxiesCORS()
}

// wireRedis builds the ONE shared Redis client when a redis block is declared,
// stashing it on the builder so every store with backend:redis fans out from it
// (one connection pool per replica, not one per store). Called first in buildApp
// so all later wireXxx can consume it. No redis block => b.redis stays nil and
// the memory/sqlite paths are byte-identical.
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

// --- helpers ---

// slogLogger adapts log/slog to the spi.Logger interface so the SDK can hand
// off to whatever sink the operator wants (stdout, journald, file...).
type slogLogger struct{ inner *slog.Logger }
