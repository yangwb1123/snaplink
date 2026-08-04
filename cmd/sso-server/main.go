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
	"time"

	"database/sql"

	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/cmd/sso-server/servermodules"
	"github.com/yangwb1123/snaplink/config"
	configreload "github.com/yangwb1123/snaplink/config/reload"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/buildinfo"
	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/operations"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"

	"github.com/yangwb1123/snaplink/domains/metering"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/platform/lifecycle/dr"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/platform/registry"
	"github.com/yangwb1123/snaplink/platform/releases"
	"github.com/yangwb1123/snaplink/platform/signingkeys"
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
	if wroteVersion() {
		return
	}
	servermodules.Register()
	if wroteModules() {
		return
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
	validateBuildCapabilities(cfg.Server.RequiredCapabilities)

	logger := newSlogLogger(cfg.Logging.Level)

	// --validate-only: load + validate config, then exit without
	// starting the server. Useful for CI and pre-deployment checks.
	if flags.validateOnly {
		logger.Info("config valid", "build_profile", buildinfo.BuildProfile, "required_capabilities", cfg.Server.RequiredCapabilities)
		return
	}

	// Go runtime tuning for consistent latency under load.
	applyRuntimeTuning(cfg.Server.HTTP2)

	tracingShutdown := initTracing(cfg, logger)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tracingShutdown(ctx)
	}()

	reloader := newConfigReloader(cfg, sources, logger)
	if err := run(cfg, logger, flags.tlsCert, flags.tlsKey, flags.grpcListen, reloader); err != nil {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

func validateBuildCapabilities(required []string) {
	if err := buildinfo.ValidateRequiredCapabilities(required); err != nil {
		fail("config capability contract: %v", err)
	}
}

// wroteVersion reports the build version before registration or config work.
func wroteVersion() bool {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "version", "-version", "--version", "-v":
			buildinfo.Write(os.Stdout, "sso-server", version)
			return true
		}
	}
	return false
}

// wroteModules reports inventory after compiled registrars have run, but
// before config loading. A successful native smoke therefore covers both.
func wroteModules() bool {
	if len(os.Args) < 2 || os.Args[1] != "modules" {
		return false
	}
	asJSON := len(os.Args) == 3 && os.Args[2] == "--json"
	if len(os.Args) > 3 || (len(os.Args) == 3 && !asJSON) {
		failUsage("usage: %s modules [--json]", progName)
	}
	if err := buildinfo.WriteModules(os.Stdout, "sso-server", asJSON); err != nil {
		fail("write module inventory: %v", err)
	}
	return true
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
	clientStore          sso.ClientStore
	userProvider         sso.UserProvider
	sessionMgr           sso.SessionManager
	consentStore         sso.ConsentStore              // for the GDPR eraser
	mfaEnrollStore       sso.MFAEnrollmentStore        // for the GDPR eraser
	passwordResetRevoker core.PasswordResetRevoker     // for the GDPR eraser
	tempStore            authenticators.TempTokenStore // may be nil when temp_token disabled
	tokenIssuers         map[string]sso.TokenIssuer

	// idTokenIssuer + refreshTokenStore are held so the WebAuthn
	// ceremony extension can issue id_token / refresh_token alongside
	// access_token (matching /auth/login's emission shape). Both nil
	// when the underlying SPI isn't wired — emission degrades silently
	// instead of breaking the ceremony.
	idTokenIssuer     oidc.IDTokenIssuer
	refreshTokenStore oauth.RefreshTokenStore
	refreshTokenTTL   time.Duration

	adminMW *sso.AdminMiddleware // nil when admin disabled

	// keyAdmin serves the on-demand signing-key rotation + list RPCs. Always
	// constructed; registered only when the admin plane is enabled.
	keyAdmin *grpcserver.KeyAdminService

	// Snapshot subsystem (Phase D-2). All four nil when snapshot disabled.
	snapshotPipeline *snapshot.Pipeline
	snapshotStorage  snapshot.Storage
	snapshotter      *snapshot.Snapshotter
	snapshotRestorer *snapshot.Restorer

	// Releases subsystem (Phase D-3). Both nil when releases disabled.
	releaseRegistry *releases.Registry
	releaseStore    releases.ReleaseStore
	operationStore  operations.Store

	// auditAsyncSink is non-nil when audit.async.enabled wraps the
	// configured sink; Close drains the buffer during shutdown.
	auditAsyncSink *audit.AsyncSink

	// auditKafkaSink is non-nil when audit.kafka.enabled wired a Kafka
	// producer sink; shutdownSubsystems Close's it (flush + disconnect) if
	// it implements interface{ Close(context.Context) error } — the
	// concrete type lives in the infrastructure/kafka nested module, which
	// this (the core) module never imports, so the field is the audit.Sink
	// interface and the Close capability is checked via type assertion.
	auditKafkaSink audit.Sink

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

	// DR subsystem (docs/dr-framework.md). drReadiness aggregates the
	// SnapshotReplicator + RecoveryTimeTracker for the admin status
	// endpoint (and, only when dr.gate_readiness opts in, the /readyz
	// check); drReplicationCancel/Done mirror the snapshot-retention pair
	// above for graceful shutdown of the background replication loop. All
	// nil unless dr.enabled.
	drReadiness         *dr.DRReadiness
	drReplicationCancel context.CancelFunc
	drReplicationDone   <-chan struct{}

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

	// Governance subsystems (wave-2 cmd wiring). Each cancel/done pair uses
	// the standard scheduler shutdown lifecycle (main_shutdown.go). All
	// nil/zero when the owning config section is disabled.
	//
	// credentialSched* — the platform/lifecycle/rotation Scheduler loop
	// (rotation.enabled). configAuditStore + configDrift* — the
	// platform/configaudit history store (closed at shutdown when it is an
	// io.Closer) + the cross-replica drift-broadcast loop (config_audit.enabled
	// with drift.interval>0). breakGlass* — the core.BreakGlassStore expiry
	// sweeper (break_glass.enabled).
	credentialSchedCancel context.CancelFunc
	credentialSchedDone   <-chan struct{}
	configAuditStore      configaudit.Store
	configDriftCancel     context.CancelFunc
	configDriftDone       <-chan struct{}
	breakGlassCancel      context.CancelFunc
	breakGlassDone        <-chan struct{}

	// continuousVerify* — the zero-trust ContinuousVerificationAgent loop
	// (session_trust_decay enabled), nil when off.
	continuousVerifyCancel context.CancelFunc
	continuousVerifyDone   <-chan struct{}
	capConvergenceCancel   context.CancelFunc
	capConvergenceDone     <-chan struct{}

	// tokenUsageRecorder is the bounded-buffer token-usage telemetry recorder
	// backing the wave-4 anomaly detector (token_anomaly.enabled); its queue is
	// drained at shutdown so events captured in the final milliseconds still feed
	// the detector. tokenAnomalySweep* stops the RunTokenAnomalyDetection loop via
	// the standard scheduler lifecycle. All nil when off.
	tokenUsageRecorder      *metering.Recorder
	tokenAnomalySweepCancel context.CancelFunc
	tokenAnomalySweepDone   <-chan struct{}

	// degradationMgr is the DR degraded-service Manager (degradation.enabled),
	// nil when off. No shutdown handle — the manager owns no goroutine; its only
	// runtime surface is the admin /api/v1/admin/dr/mode toggle. Held so the mode
	// is inspectable and an external health loop can drive SetMode.
	degradationMgr *sso.DegradationManager

	// userAutoDeprovisionCancel/Done stop the domains/userlifecycle
	// dormancy-sweep loop (user_lifecycle.auto_deprovision.enabled); nil/zero
	// when off.
	userAutoDeprovisionCancel context.CancelFunc
	userAutoDeprovisionDone   <-chan struct{}

	// redisClient is the one shared Redis client fanned out to every
	// redis-backed store; nil when no redis block is configured. Closed once at
	// shutdown to release its connection pool.
	redisClient goredis.UniversalClient

	// pgDB is the one shared Postgres-wire pool fanned out to every
	// postgres-backed durable store; nil when no postgres block is configured.
	// Closed once at shutdown.
	pgDB *sql.DB
}

func run(cfg *config.Config, logger spi.Logger, tlsCert, tlsKey, grpcListen string, reloader *configreload.Reloader) error {
	a, err := buildApp(cfg, logger)
	if err != nil {
		return err
	}
	defer closeAppStores(a)
	wireRateLimitReload(reloader, a.server, a.redisClient)
	wireFeatureGateReload(reloader, a.server)

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

	if err := waitForShutdown(logger, errCh, reloader); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	closeSSEBroker(a)
	shutdownServers(ctx, logger, httpSrv, pprofSrv, grpcSrv)
	shutdownSubsystems(ctx, a, logger)
	logger.Info("server stopped cleanly")
	return nil
}
