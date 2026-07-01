// Command sso-server is the production binary that wires up the snaplink/sso
// SDK into a runnable HTTP service. It loads a YAML config (see
// deploy/openresty/README.md for an example), supports graceful shutdown on
// SIGINT/SIGTERM, applies sensible HTTP timeouts, and (optionally) terminates
// TLS itself or sits behind an OpenResty / Envoy / NGINX reverse proxy.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"database/sql"

	goredis "github.com/redis/go-redis/v9"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/authenticators/webauthn"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/buildinfo"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/infrastructure/defaultimpl"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/platform/registry"
	"github.com/snaplink/sso/platform/releases"
	"github.com/snaplink/sso/platform/signingkeys"
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

// version is overridable at build time via -ldflags "-X main.version=v1.2.3";
// otherwise buildinfo derives it from the embedded module/VCS build info.
var version = ""

func main() {
	// Report version and exit before any config work, so `sso-server version`
	// (or -version) works without a valid config file. The server itself runs
	// directly (no `run` subcommand) — `sso-server [-config ...]` is the
	// conventional, unchanged invocation.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "version", "-version", "--version", "-v":
			buildinfo.Write(os.Stdout, "sso-server", version)
			return
		}
	}

	flags := parseRuntimeFlags()

	sources, cleanupSources, err := buildConfigSources(flags)
	if err != nil {
		fail("config/etcd: %v", err)
	}
	// Keep the etcd connection (if any) open for the process lifetime; see
	// buildConfigSources for why holding it open is cheap and safer here.
	defer cleanupSources()

	cfg, err := config.LoadFromSources(context.Background(), sources...)
	if err != nil {
		fail("config: %v", err)
	}

	logger := newSlogLogger(cfg.Logging.Level)

	// --validate-only: load + validate config, then exit without
	// starting the server. Useful for CI and pre-deployment checks.
	if flags.validateOnly {
		logger.Info("config valid")
		return
	}

	// Go runtime tuning for consistent latency under load.
	applyRuntimeTuning()

	tracingShutdown := initTracing(cfg, logger)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tracingShutdown(ctx)
	}()

	if err := run(cfg, logger, flags.tlsCert, flags.tlsKey, flags.grpcListen); err != nil {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

// applyRuntimeTuning adjusts Go runtime parameters for SSO-server workloads.
// High-throughput token signing creates many short-lived objects; a higher
// GC target reduces GC frequency at the cost of a small heap increase.
func applyRuntimeTuning() {
	// GC target: 200% instead of the default 100% — fewer GC cycles
	// under spiky token-issuance load. Respects explicit env override.
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(200)
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
	clientStore    sso.ClientStore
	userProvider   sso.UserProvider
	sessionMgr     sso.SessionManager
	consentStore   sso.ConsentStore              // for the GDPR eraser
	mfaEnrollStore sso.MFAEnrollmentStore        // for the GDPR eraser
	tempStore      authenticators.TempTokenStore // may be nil when temp_token disabled
	tokenIssuers   map[string]sso.TokenIssuer

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

	// refreshGracePruneCancel + refreshGracePruneDone — same pattern for
	// the refresh_grace_cache cleanup goroutine. SQLite backend only.
	refreshGracePruneCancel context.CancelFunc
	refreshGracePruneDone   <-chan struct{}

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

	// redisClient is the one shared Redis client fanned out to every
	// redis-backed store; nil when no redis block is configured. Closed once at
	// shutdown to release its connection pool.
	redisClient goredis.UniversalClient

	// pgDB is the one shared Postgres-wire pool fanned out to every
	// postgres-backed durable store; nil when no postgres block is configured.
	// Closed once at shutdown.
	pgDB *sql.DB
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

	grpcSrv, err := startGRPCServer(a, grpcListen, logger, tlsCert, tlsKey, errCh)
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
