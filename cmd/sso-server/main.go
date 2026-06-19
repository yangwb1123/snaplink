// Command sso-server is the production binary that wires up the snaplink/sso
// SDK into a runnable HTTP service. It loads a YAML config (see
// deploy/openresty/README.md for an example), supports graceful shutdown on
// SIGINT/SIGTERM, applies sensible HTTP timeouts, and (optionally) terminates
// TLS itself or sits behind an OpenResty / Envoy / NGINX reverse proxy.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/authenticators/webauthn"
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/spi"

	configetcd "github.com/snaplink/sso/config/etcd"
	"github.com/snaplink/sso/connections"
	"github.com/snaplink/sso/defaultimpl"

	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/registry"
	"github.com/snaplink/sso/releases"
	"github.com/snaplink/sso/signingkeys"
	"github.com/snaplink/sso/snapshot"
	"github.com/snaplink/sso/tenant"
	"github.com/snaplink/sso/tracing"
)

// HTTP server timeouts. Liberal enough for slow mobile networks, tight enough
// to cap goroutine pile-up from hung clients.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 15 * time.Second

	adminAPIPathPrefix = "/api/v1/admin/"

	bootstrapNamespace = "sso-server"
)

func main() {
	flag.Usage = usage
	// Bound to Config fields via FlagSource below. The values themselves
	// aren't read directly — Loader resolves them when building *Config,
	// so a flag without --foo on argv leaves the file / env value alone.
	cfgPath := flag.String("config", "config.yaml", "path to YAML config")
	_ = flag.String("listen", "", "override server.listen from config (e.g. :9090)")
	_ = flag.String("log-level", "", "override logging.level (debug|info|error)")
	_ = flag.String("bootstrap-restore-from", "", "snapshot URI for first-boot restore (overrides snapshot.restore_from); e.g. file:///var/snapshots/snap.snap")
	_ = flag.String("bootstrap-admin-password-file", "", "path to write the generated admin password to (mode 0600), in addition to stdout; overrides bootstrap.admin_password_file")

	// Runtime-only flags: not in Config (yet) — passed directly to run().
	grpcListen := flag.String("grpc-listen", ":8081", "gRPC listen address ('' to disable)")
	tlsCert := flag.String("tls-cert", "", "TLS cert file (omit for HTTP)")
	tlsKey := flag.String("tls-key", "", "TLS key file (omit for HTTP)")

	// Optional centralized config: when --etcd-endpoints is set, an etcd
	// Source slots into the Loader chain between env and flag, so a
	// cluster-wide value beats the local file + env but a one-shot CLI
	// override still wins. Endpoints empty = skip (etcd is an optional
	// operator-side dep, not a runtime requirement).
	etcdEndpoints := flag.String("etcd-endpoints", "", "comma-separated etcd endpoints for live config; empty disables (e.g. localhost:2379)")
	etcdPrefix := flag.String("etcd-prefix", configetcd.DefaultPrefix, "etcd key prefix when --etcd-endpoints is set")
	flag.Parse()

	// Loader chain — priority low → high: file < env < etcd? < flag.
	// Operators drop a YAML file for the bulk of config, sprinkle ENV in
	// container orchestrators (12-factor), opt into etcd for cluster-wide
	// live values, and use CLI flags for ad-hoc overrides (debugging,
	// one-shot reruns).
	flagSrc := config.NewFlagSource(flag.CommandLine).
		Bind("listen", "server.listen").
		Bind("log-level", "logging.level").
		Bind("bootstrap-restore-from", "snapshot.restore_from").
		Bind("bootstrap-admin-password-file", "bootstrap.admin_password_file")

	sources := []config.Source{
		config.NewFileSource(*cfgPath),
		config.NewEnvSource(),
	}
	if *etcdEndpoints != "" {
		etcdSrc, err := configetcd.New(configetcd.Config{
			Endpoints: strings.Split(*etcdEndpoints, ","),
			Prefix:    *etcdPrefix,
		})
		if err != nil {
			fail("config/etcd: %v", err)
		}
		// Keep the connection open for the process lifetime. The Source
		// only does one Get on Load and doesn't watch — cheap to hold
		// open and avoids the close-on-error edge case if Load fails.
		defer func() { _ = etcdSrc.Close() }()
		sources = append(sources, etcdSrc)
	}
	sources = append(sources, flagSrc)

	cfg, err := config.LoadFromSources(context.Background(), sources...)
	if err != nil {
		fail("config: %v", err)
	}

	logger := newSlogLogger(cfg.Logging.Level)

	// OTLP tracing — no-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset,
	// so this call is safe to leave unconditional. Shutdown flushes
	// pending spans on process exit.
	tracingShutdown, err := tracing.Init(context.Background(),
		tracing.WithServiceName(cfg.Server.Issuer),
	)
	if err != nil {
		logger.Error("tracing init failed; continuing without traces", "error", err)
		tracingShutdown = func(context.Context) error { return nil }
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tracingShutdown(ctx)
	}()

	if err := run(cfg, logger, *tlsCert, *tlsKey, *grpcListen); err != nil {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

// app bundles the wired SDK components so both HTTP and gRPC servers can
// reuse the same Recorder / Provider / Registry / netpolicy instances.
type app struct {
	server     *sso.Server
	recorder   *audit.Recorder
	provider   permissions.Provider
	registry   registry.Registry
	netStore   netpolicy.Store       // nil when network disabled
	classifier *netpolicy.Classifier // nil when network disabled

	// Admin-plane dependencies. Held as concrete references so admin RPCs +
	// bootstrap steps can mutate the same backing stores the SDK runtime
	// reads from.
	clientStore  sso.ClientStore
	userProvider sso.UserProvider
	sessionMgr   sso.SessionManager
	tempStore    authenticators.TempTokenStore // may be nil when temp_token disabled
	tokenIssuers map[string]sso.TokenIssuer

	// idTokenIssuer + refreshTokenStore are held so the WebAuthn
	// ceremony extension can issue id_token / refresh_token alongside
	// access_token (matching /auth/login's emission shape). Both nil
	// when the underlying SPI isn't wired — emission degrades silently
	// instead of breaking the ceremony.
	idTokenIssuer     oidc.IDTokenIssuer
	refreshTokenStore oauth.RefreshTokenStore
	refreshTokenTTL   time.Duration

	adminMW *sso.AdminMiddleware // nil when admin disabled

	// Snapshot subsystem (Phase D-2). All four nil when snapshot disabled.
	snapshotPipeline *snapshot.Pipeline
	snapshotStorage  snapshot.Storage
	snapshotter      *snapshot.Snapshotter
	snapshotRestorer *snapshot.Restorer

	// Releases subsystem (Phase D-3). Both nil when releases disabled.
	releaseRegistry *releases.Registry
	releaseStore    releases.ReleaseStore

	// auditAsyncSink is non-nil when audit.async.enabled wraps the
	// configured sink; Close drains the buffer during shutdown.
	auditAsyncSink *audit.AsyncSink

	// auditRetentionCancel + auditRetentionDone coordinate the
	// background prune loop's shutdown when audit.retention.enabled
	// wires it. Cancel signals; Done closes when the goroutine
	// exits. Both nil when the loop isn't running (memory backend
	// or retention.enabled=false).
	auditRetentionCancel context.CancelFunc
	auditRetentionDone   <-chan struct{}

	// snapshotRetentionCancel + snapshotRetentionDone mirror the
	// audit retention pair for snapshot retention.
	snapshotRetentionCancel context.CancelFunc
	snapshotRetentionDone   <-chan struct{}

	// pushPruneCancel + pushPruneDone — same pattern for the
	// PushApprovalStore PruneExpired loop. SQLite backend only;
	// memory store self-prunes via Get's expiry check.
	pushPruneCancel context.CancelFunc
	pushPruneDone   <-chan struct{}

	// cibaPruneCancel + cibaPruneDone — same pattern for the CIBA
	// request store PruneExpired loop. SQLite backend only; memory
	// store self-prunes via Get's expiry check.
	cibaPruneCancel context.CancelFunc
	cibaPruneDone   <-chan struct{}

	// pushApprovalStore is the SQLite-backed handle (or nil for
	// memory backend / no push factor). Held so buildHTTPHandler
	// can wire the reference callback handler against it.
	pushApprovalStore defaultimpl.PushApprovalStore

	// pushNotify is the channel-notify wakeup for the push provider
	// (nil unless mfa.provider.push.channel_notify=true). buildHTTPHandler
	// hands it to the reference callback so an approve/deny wakes a
	// blocked Verify immediately instead of after a poll tick.
	pushNotify func(approvalID string)

	// anomalyRT is the lifecycle handle for the async anomaly
	// detection subsystem. Nil when anomaly.enabled=false. Drained
	// + closed during shutdown.
	anomalyRT *anomalyRuntime

	// metrics handle is held so subsystems wired after the SSO
	// server (e.g. WebAuthn route mounting in buildHTTPHandler)
	// can emit on their own counters. Nil when cfg.Metrics.Enabled
	// is false.
	metrics *metrics.Metrics

	// Tenant store (multi-tenant routing). Nil when disabled. Closed
	// during shutdown so SQL backends release their connections.
	tenantStore tenant.Store

	// connectionStore holds per-organization enterprise connections for B2B
	// home-realm discovery. Nil when disabled. Closed during shutdown.
	connectionStore connections.Store

	// regionResolver is the serving-region resolver (nil when region is
	// unconfigured). Held so buildHTTPHandler can plumb it — together with
	// the server's context-free ResidencyDecision seam — into webauthnDeps,
	// closing the data-residency hole on the WebAuthn login mint path (the
	// ceremony is mounted as raw http handlers OUTSIDE the HandlerContext
	// residency gate). Nil ⇒ WebAuthn residency check stays off (byte-identical).
	regionResolver region.Resolver

	// webauthnHelper is non-nil when webauthn.enabled. Ceremony routes
	// hang off the same SSO router via Server.Handle. The helper holds
	// references to the UserStore + SessionStore — Close lives on those
	// stores directly when the backend is SQLite.
	webauthnHelper *webauthn.Helper

	// netStop closes when the Classifier's Watch loop exits (after shutdown).
	netStop <-chan struct{}
	// netCancel stops the Classifier's self-healing Watch loop at shutdown so
	// it exits cleanly instead of treating the store-Close as a Watch failure
	// (which would flip degraded + churn reconnects on the way out). nil when
	// network policy is disabled.
	netCancel context.CancelFunc

	// invalidationBus is the cross-replica cache-coordination bus (nil
	// when unconfigured); busStop closes when its subscriber exits.
	invalidationBus cluster.Bus
	busStop         <-chan struct{}

	// signingKeyRegistry is the opt-in leaderless multi-replica signing-key
	// aggregation registry (nil when unconfigured); signingKeyStop closes
	// when its subscriber exits.
	signingKeyRegistry signingkeys.Registry
	signingKeyStop     <-chan struct{}

	// keyRotationCancel stops the signing-key rotation loop (nil when
	// rotation is disabled); keyRotationStop closes when it has exited.
	keyRotationCancel context.CancelFunc
	keyRotationStop   <-chan struct{}
}

func run(cfg *config.Config, logger spi.Logger, tlsCert, tlsKey, grpcListen string) error {
	a, err := buildApp(cfg, logger)
	if err != nil {
		return err
	}
	defer closeAppStores(a)

	// Phase C: bootstrap runner — applies pending init steps (seed admin
	// role, admin user, default netpolicy, admin client). Must complete
	// before we accept admin RPCs, so we run synchronously here.
	if !cfg.Bootstrap.Disabled {
		if err := runBootstrap(cfg, a, logger); err != nil {
			return fmt.Errorf("bootstrap: %w", err)
		}
	}

	httpSrv, err := buildHTTPServer(cfg, a, logger)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	startHTTPServer(httpSrv, cfg, logger, tlsCert, tlsKey, errCh)
	pprofSrv := startPprofServer(cfg, logger)

	grpcSrv, err := startGRPCServer(a, grpcListen, logger, errCh)
	if err != nil {
		return err
	}

	logEndpoints(cfg, grpcListen)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	shutdownServers(ctx, logger, httpSrv, pprofSrv, grpcSrv)
	shutdownSubsystems(ctx, a, logger)
	logger.Info("server stopped cleanly")
	return nil
}
