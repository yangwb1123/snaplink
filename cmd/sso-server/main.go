// Command sso-server is the production binary that wires up the snaplink/sso
// SDK into a runnable HTTP service. It loads a YAML config (see
// deploy/openresty/README.md for an example), supports graceful shutdown on
// SIGINT/SIGTERM, applies sensible HTTP timeouts, and (optionally) terminates
// TLS itself or sits behind an OpenResty / Envoy / NGINX reverse proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
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

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"

	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"

	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"

	discoveryv1 "github.com/snaplink/sso/gen/proto/discovery/v1"

	netpolicyv1 "github.com/snaplink/sso/gen/proto/netpolicy/v1"
	"github.com/snaplink/sso/grpcserver"
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
	"google.golang.org/grpc"
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
	defer func() { _ = a.registry.Close() }()
	if a.netStore != nil {
		defer func() { _ = a.netStore.Close() }()
	}
	if a.tenantStore != nil {
		defer func() { _ = a.tenantStore.Close() }()
	}
	// connections.Store has no Close on the interface; the sqlite backend does.
	if c, ok := a.connectionStore.(io.Closer); ok {
		defer func() { _ = c.Close() }()
	}

	// Phase C: bootstrap runner — applies pending init steps (seed admin
	// role, admin user, default netpolicy, admin client). Must complete
	// before we accept admin RPCs, so we run synchronously here.
	if !cfg.Bootstrap.Disabled {
		if err := runBootstrap(cfg, a, logger); err != nil {
			return fmt.Errorf("bootstrap: %w", err)
		}
	}

	httpHandler, err := buildHTTPHandler(cfg, a, logger)
	if err != nil {
		return fmt.Errorf("http handler: %w", err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           httpHandler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	errCh := make(chan error, 2)
	go func() {
		var serveErr error
		if tlsCert != "" && tlsKey != "" {
			logger.Info("http listening (TLS)", "addr", cfg.Server.Listen)
			serveErr = httpSrv.ListenAndServeTLS(tlsCert, tlsKey)
		} else {
			logger.Info("http listening", "addr", cfg.Server.Listen)
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http: %w", serveErr)
			return
		}
		errCh <- nil
	}()

	// Optional pprof on a SEPARATE listener bound to a trusted interface
	// (default 127.0.0.1:6060). Never mounted on the public router — pprof
	// leaks memory contents and the CPU profile is a DoS vector. Failure is
	// non-fatal (log-only): profiling is observability, not a serving path.
	// An explicit mux (not DefaultServeMux) keeps the handlers off any other
	// server the process might run.
	var pprofSrv *http.Server
	if cfg.Server.Pprof.Enabled {
		pprofAddr := cfg.Server.Pprof.Listen
		if pprofAddr == "" {
			pprofAddr = "127.0.0.1:6060"
		}
		pmux := http.NewServeMux()
		pmux.HandleFunc("/debug/pprof/", pprof.Index)
		pmux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pmux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pmux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pmux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		pprofSrv = &http.Server{Addr: pprofAddr, Handler: pmux, ReadHeaderTimeout: readHeaderTimeout}
		go func() {
			logger.Info("pprof listening", "addr", pprofAddr)
			if err := pprofSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("pprof server failed", "error", err)
			}
		}()
	}

	var grpcSrv *grpc.Server
	if grpcListen != "" {
		grpcSrv = newGRPCServer(a)
		ln, err := net.Listen("tcp", grpcListen)
		if err != nil {
			return fmt.Errorf("grpc listen: %w", err)
		}
		go func() {
			logger.Info("grpc listening", "addr", grpcListen)
			if err := grpcSrv.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				errCh <- fmt.Errorf("grpc: %w", err)
				return
			}
			errCh <- nil
		}()
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
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("http graceful shutdown failed", "error", err)
		_ = httpSrv.Close()
	}
	if pprofSrv != nil {
		_ = pprofSrv.Shutdown(ctx)
	}
	if grpcSrv != nil {
		stopped := make(chan struct{})
		go func() { grpcSrv.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-ctx.Done():
			logger.Error("grpc graceful shutdown timed out — forcing stop")
			grpcSrv.Stop()
		}
	}
	// Cancel the Classifier's watch loop so it exits cleanly (no spurious
	// degraded flip), then wait briefly for it to drain any in-flight Apply
	// events before we drop the store reference.
	if a.netCancel != nil {
		a.netCancel()
	}
	if a.netStop != nil {
		select {
		case <-a.netStop:
		case <-ctx.Done():
		}
	}
	// Close the invalidation bus so its subscriber Watch loop exits, then
	// wait briefly for that goroutine to drain — same shape as netStop.
	if a.invalidationBus != nil {
		_ = a.invalidationBus.Close()
	}
	if a.busStop != nil {
		select {
		case <-a.busStop:
		case <-ctx.Done():
		}
	}
	// Close the signing-key registry so its subscriber stream exits, then
	// wait briefly for that goroutine to drain — same shape as busStop.
	if a.signingKeyRegistry != nil {
		_ = a.signingKeyRegistry.Close()
	}
	if a.signingKeyStop != nil {
		select {
		case <-a.signingKeyStop:
		case <-ctx.Done():
		}
	}
	// Stop the signing-key rotation loop and wait for it to exit.
	if a.keyRotationCancel != nil {
		a.keyRotationCancel()
	}
	if a.keyRotationStop != nil {
		select {
		case <-a.keyRotationStop:
		case <-ctx.Done():
		}
	}
	// Stop the audit retention scheduler BEFORE draining the
	// AsyncSink so an in-flight Prune doesn't race the close. The
	// scheduler exits within the bounded shutdown ctx; if it's
	// mid-Prune we wait for it (Prune is bounded by SQLite's
	// transaction time which is typically <1s on retention runs).
	if a.auditRetentionCancel != nil {
		a.auditRetentionCancel()
		if a.auditRetentionDone != nil {
			select {
			case <-a.auditRetentionDone:
			case <-ctx.Done():
				logger.Error("audit retention scheduler did not exit cleanly")
			}
		}
	}
	// Snapshot retention scheduler: same pattern. Cancel + bounded
	// wait. Loop body is List + (k-N)*Delete; bounded by storage
	// backend Delete latency.
	if a.snapshotRetentionCancel != nil {
		a.snapshotRetentionCancel()
		if a.snapshotRetentionDone != nil {
			select {
			case <-a.snapshotRetentionDone:
			case <-ctx.Done():
				logger.Error("snapshot retention scheduler did not exit cleanly")
			}
		}
	}
	// Push approval pruner: same pattern.
	if a.pushPruneCancel != nil {
		a.pushPruneCancel()
		if a.pushPruneDone != nil {
			select {
			case <-a.pushPruneDone:
			case <-ctx.Done():
				logger.Error("push approval pruner did not exit cleanly")
			}
		}
	}
	// CIBA request pruner: same pattern.
	if a.cibaPruneCancel != nil {
		a.cibaPruneCancel()
		if a.cibaPruneDone != nil {
			select {
			case <-a.cibaPruneDone:
			case <-ctx.Done():
				logger.Error("ciba request pruner did not exit cleanly")
			}
		}
	}
	// Anomaly detection: drain queue + close SQLite stores. Bounded
	// by the same shutdown ctx so a hung detector backend can't
	// stall the whole process.
	if a.anomalyRT != nil {
		a.anomalyRT.close(ctx)
	}
	// Drain the audit AsyncSink queue under the same shutdown
	// deadline. Events queued during the final ~milliseconds before
	// SIGTERM matter — they're typically the shutdown events
	// themselves (admin logout, snapshot rotation). Best-effort:
	// remaining events are silently dropped when the deadline fires.
	if a.auditAsyncSink != nil {
		if err := a.auditAsyncSink.Close(ctx); err != nil {
			logger.Error("audit async drain timed out", "error", err)
		}
	}
	// Drain in-flight CAEP SET pushes so a shutting-down replica doesn't
	// abandon a goroutine mid-POST. Bounded by the shutdown ctx; each send
	// also has its own per-receiver timeout.
	if a.server != nil {
		if tx := a.server.CAEPTransmitter(); tx != nil {
			if err := tx.Close(ctx); err != nil {
				logger.Error("caep transmitter drain timed out", "error", err)
			}
		}
	}
	logger.Info("server stopped cleanly")
	return nil
}

// newGRPCServer registers every available service on a fresh grpc.Server.
// Phase A: AuditWriter, Authorizer, Discovery (always). Phase B:
// PolicyService when network is enabled. Phase C: 4 admin services when
// admin is enabled — gated by AdminMiddleware's UnaryServerInterceptor.
func newGRPCServer(a *app) *grpc.Server {
	var opts []grpc.ServerOption
	if a.adminMW != nil {
		opts = append(opts, grpc.UnaryInterceptor(a.adminMW.UnaryServerInterceptor()))
	}
	s := grpc.NewServer(opts...)
	auditv1.RegisterAuditWriterServer(s, grpcserver.NewAuditService(a.recorder))
	authzv1.RegisterAuthorizerServer(s, grpcserver.NewAuthzService(a.provider))
	discoveryv1.RegisterDiscoveryServer(s, grpcserver.NewDiscoveryService(a.registry))
	if a.netStore != nil {
		netpolicyv1.RegisterPolicyServiceServer(s, grpcserver.NewNetPolicyService(a.netStore, a.classifier, a.recorder))
	}
	if a.adminMW != nil {
		adminv1.RegisterClientAdminServiceServer(s, grpcserver.NewClientAdminService(a.clientStore, a.recorder, a.server.InvalidateDiscoveryCache, a.server.InvalidateClientCache))
		adminv1.RegisterUserAdminServiceServer(s, grpcserver.NewUserAdminService(a.userProvider, a.sessionMgr, a.recorder))
		adminv1.RegisterTokenAdminServiceServer(s, grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
			Sessions:  a.sessionMgr,
			TempStore: a.tempStore,
			Issuers:   a.tokenIssuers,
			Recorder:  a.recorder,
		}))
		adminv1.RegisterPermissionAdminServiceServer(s, grpcserver.NewPermissionAdminService(
			a.provider, a.recorder,
			func(_ context.Context, id string) { a.server.InvalidateAuthzPolicyBundleCache(id) }))
		if a.snapshotPipeline != nil {
			adminv1.RegisterSnapshotAdminServiceServer(s, grpcserver.NewSnapshotAdminService(
				a.snapshotPipeline, a.snapshotStorage, a.snapshotter, a.snapshotRestorer, a.recorder))
		}
		if a.releaseStore != nil {
			adminv1.RegisterReleaseAdminServiceServer(s, grpcserver.NewReleaseAdminService(
				a.releaseRegistry, a.releaseStore, a.recorder))
		}
		if a.tenantStore != nil {
			adminv1.RegisterTenantAdminServiceServer(s, grpcserver.NewTenantAdminService(
				a.tenantStore, a.recorder, a.server.InvalidateTenantSuspensionCache,
				a.server.InvalidateTenantResidencyCache,
				func(ctx context.Context, id string) { _, _ = a.server.RevokeTenantRefreshTokens(ctx, id) }))
		}
	}
	return s
}

// buildHTTPHandler composes the SSO Server's runtime handler with the
// optional grpc-gateway admin reverse proxy. The gateway is mounted under
// /api/v1/admin/ and gated by AdminMiddleware (bearer + admin scope).

func newSlogLogger(level string) *slogLogger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return &slogLogger{inner: slog.New(h)}
}

func (l *slogLogger) Info(msg string, kv ...any)  { l.inner.Info(msg, kv...) }
func (l *slogLogger) Error(msg string, kv ...any) { l.inner.Error(msg, kv...) }
func (l *slogLogger) Debug(msg string, kv ...any) { l.inner.Debug(msg, kv...) }

// slogLogger implements spi.ContextLogger: the *Ctx variants append the
// W3C trace_id the SDK stamped onto ctx (parsed from the request's
// traceparent — the same id that lands on audit Event.TraceID), so ops
// log lines join to traces + audit. Absent trace → no field emitted.
// trace_id is LOG-ONLY; it never touches a wire response.
var _ spi.ContextLogger = (*slogLogger)(nil)

func (l *slogLogger) InfoCtx(ctx context.Context, msg string, kv ...any) {
	l.inner.Info(msg, withTraceID(ctx, kv)...)
}

func (l *slogLogger) ErrorCtx(ctx context.Context, msg string, kv ...any) {
	l.inner.Error(msg, withTraceID(ctx, kv)...)
}

func (l *slogLogger) DebugCtx(ctx context.Context, msg string, kv ...any) {
	l.inner.Debug(msg, withTraceID(ctx, kv)...)
}

// withTraceID appends a trace_id key/value to kv when ctx carries a W3C
// trace id, otherwise returns kv unchanged.
func withTraceID(ctx context.Context, kv []any) []any {
	if tid := spi.TraceIDFromContext(ctx); tid != "" {
		return append(kv, slog.String("trace_id", tid))
	}
	return kv
}

// progName prefixes every diagnostic so multi-binary deployments can
// tell which tool emitted a line.
const progName = "sso-server"

// usage prints the standard "<prog> — <desc> / Usage / Flags" banner
// shared in style across the sso-* CLIs. Wired as flag.Usage so -h and
// parse errors render it.
func usage() {
	fmt.Fprint(os.Stderr, progName+` — OAuth 2.0 / OIDC SSO server.

Usage:
  `+progName+` [flags]

Flags:
`)
	flag.PrintDefaults()
}

// fail prints "<prog>: <msg>" to stderr and exits 1 (runtime error).
// CLI-misuse errors should exit 2 via flag.Usage instead.
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	os.Exit(1)
}

// writeAdminPasswordFile atomically writes the bootstrap admin
// password to path at mode 0600. Atomicity (tmp + rename) prevents
// a crashed write from leaving a half-empty file the operator
// might trust as authoritative. Parent directory must exist —
// not auto-created so an operator who points at /secrets/admin
// without mounting the volume sees the error rather than the
// password landing somewhere unexpected.
func writeAdminPasswordFile(path, password string) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".admin-password-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	// chmod BEFORE writing so a concurrent reader can't observe
	// 0644 in the brief window before the rename.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.WriteString(password + "\n"); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
