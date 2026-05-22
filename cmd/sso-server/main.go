// Command sso-server is the production binary that wires up the snaplink/sso
// SDK into a runnable HTTP service. It loads a YAML config (see
// deploy/openresty/README.md for an example), supports graceful shutdown on
// SIGINT/SIGTERM, applies sensible HTTP timeouts, and (optionally) terminates
// TLS itself or sits behind an OpenResty / Envoy / NGINX reverse proxy.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	auditsqlite "github.com/snaplink/sso/audit/sqlite"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/authenticators/webauthn"
	"github.com/snaplink/sso/bootstrap"
	"github.com/snaplink/sso/bootstrap/builtin"
	bootstrapfile "github.com/snaplink/sso/bootstrap/file"
	"github.com/snaplink/sso/bootstrap/lock"
	lockEtcd "github.com/snaplink/sso/bootstrap/lock/etcd"
	lockFile "github.com/snaplink/sso/bootstrap/lock/file"
	lockNoop "github.com/snaplink/sso/bootstrap/lock/noop"
	"github.com/snaplink/sso/config"
	configetcd "github.com/snaplink/sso/config/etcd"
	"github.com/snaplink/sso/cors"
	"github.com/snaplink/sso/defaultimpl"
	sqlitestores "github.com/snaplink/sso/defaultimpl/sqlite"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"
	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	discoveryv1 "github.com/snaplink/sso/gen/proto/discovery/v1"
	netpolicyv1 "github.com/snaplink/sso/gen/proto/netpolicy/v1"
	"github.com/snaplink/sso/geo"
	geostatic "github.com/snaplink/sso/geo/static"
	"github.com/snaplink/sso/grpcserver"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/netpolicy"
	netpolicyetcd "github.com/snaplink/sso/netpolicy/etcd"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ratelimit"
	"github.com/snaplink/sso/registry"
	registryetcd "github.com/snaplink/sso/registry/etcd"
	"github.com/snaplink/sso/registry/memory"
	"github.com/snaplink/sso/releases"
	releasedocker "github.com/snaplink/sso/releases/pinner/docker"
	releasenoop "github.com/snaplink/sso/releases/pinner/noop"
	releasestatic "github.com/snaplink/sso/releases/pinner/static"
	releasehttpprobe "github.com/snaplink/sso/releases/probe/http"
	releasefile "github.com/snaplink/sso/releases/store/file"
	releasememory "github.com/snaplink/sso/releases/store/memory"
	"github.com/snaplink/sso/snapshot"
	encryptionnone "github.com/snaplink/sso/snapshot/encryption/none"
	encryptionpass "github.com/snaplink/sso/snapshot/encryption/passphrase"
	storagefile "github.com/snaplink/sso/snapshot/storage/file"
	storageinline "github.com/snaplink/sso/snapshot/storage/inline"
	"github.com/snaplink/sso/tenant"
	tenantmemory "github.com/snaplink/sso/tenant/memory"
	"github.com/snaplink/sso/tracing"
	"golang.org/x/crypto/bcrypt"
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
	idTokenIssuer     sso.IDTokenIssuer
	refreshTokenStore sso.RefreshTokenStore
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

	// Tenant store (multi-tenant routing). Nil when disabled. Closed
	// during shutdown so SQL backends release their connections.
	tenantStore tenant.Store

	// webauthnHelper is non-nil when webauthn.enabled. Ceremony routes
	// hang off the same SSO router via Server.Handle. The helper holds
	// references to the UserStore + SessionStore — Close lives on those
	// stores directly when the backend is SQLite.
	webauthnHelper *webauthn.Helper

	// netStop closes when the Classifier's Watch loop exits (after shutdown).
	netStop <-chan struct{}
}

func run(cfg *config.Config, logger sso.Logger, tlsCert, tlsKey, grpcListen string) error {
	a, err := buildApp(cfg, logger)
	if err != nil {
		return err
	}
	defer a.registry.Close()
	if a.netStore != nil {
		defer a.netStore.Close()
	}
	if a.tenantStore != nil {
		defer a.tenantStore.Close()
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
	// Wait briefly for the Classifier's watch loop to exit, so any in-flight
	// Apply events are flushed before we drop the store reference.
	if a.netStop != nil {
		select {
		case <-a.netStop:
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
		adminv1.RegisterClientAdminServiceServer(s, grpcserver.NewClientAdminService(a.clientStore, a.recorder))
		adminv1.RegisterUserAdminServiceServer(s, grpcserver.NewUserAdminService(a.userProvider, a.sessionMgr, a.recorder))
		adminv1.RegisterTokenAdminServiceServer(s, grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
			Sessions:  a.sessionMgr,
			TempStore: a.tempStore,
			Issuers:   a.tokenIssuers,
			Recorder:  a.recorder,
		}))
		adminv1.RegisterPermissionAdminServiceServer(s, grpcserver.NewPermissionAdminService(a.provider, a.recorder))
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
				a.tenantStore, a.recorder, a.server.InvalidateTenantSuspensionCache))
		}
	}
	return s
}

// buildHTTPHandler composes the SSO Server's runtime handler with the
// optional grpc-gateway admin reverse proxy. The gateway is mounted under
// /api/v1/admin/ and gated by AdminMiddleware (bearer + admin scope).
func buildHTTPHandler(cfg *config.Config, a *app, logger sso.Logger) (http.Handler, error) {
	base := a.server.Handler()
	// WebAuthn ceremony routes mount on the SSO router itself so they
	// share the same middleware stack (tracing, metrics, rate-limit,
	// CORS) the built-in endpoints use. Mount AFTER Handler() so the
	// router has been initialized — Handle errors otherwise.
	if a.webauthnHelper != nil {
		deps := &webauthnDeps{
			Helper:            a.webauthnHelper,
			ClientStore:       a.clientStore,
			TokenIssuers:      a.tokenIssuers,
			DefaultStrat:      cfg.Server.DefaultTokenStrategy,
			RefreshTokenStore: a.refreshTokenStore,
			RefreshTokenTTL:   a.refreshTokenTTL,
			IDTokenIssuer:     a.idTokenIssuer,
		}
		if err := mountWebAuthnRoutes(a.server, deps); err != nil {
			return nil, fmt.Errorf("mount webauthn: %w", err)
		}
		logger.Info("webauthn routes mounted",
			"register_begin", pathWebAuthnRegistrationBegin,
			"register_finish", pathWebAuthnRegistrationFinish,
			"login_begin", pathWebAuthnLoginBegin,
			"login_finish", pathWebAuthnLoginFinish,
		)
	}
	// Wrap base with the admin middleware so /api/v1/audit/* and
	// /api/v1/netpolicy/policies* + /classify get the same Bearer +
	// scope gate as /api/v1/admin/*. isAdminProtectedPath inside
	// AdminMiddleware decides per-path; everything else passes
	// through untouched. When admin is disabled, audit + netpolicy
	// stay open (single-tenant / firewall-protected story) and we
	// log a warning so the operator notices.
	if a.adminMW != nil {
		base = a.adminMW.HTTPMiddleware(base)
	} else if cfg.Audit.APIEnabled || (cfg.Network.Enabled && cfg.Network.APIEnabled) {
		logger.Error("admin disabled: /api/v1/audit and /api/v1/netpolicy/policies endpoints will be served UNAUTHENTICATED. Production deployments MUST enable admin so bearer auth is enforced.")
	}
	if a.adminMW == nil || !cfg.Admin.APIRESTEnabled {
		return base, nil
	}
	gw := runtime.NewServeMux()
	ctx := context.Background()
	if err := adminv1.RegisterClientAdminServiceHandlerServer(ctx, gw, grpcserver.NewClientAdminService(a.clientStore, a.recorder)); err != nil {
		return nil, fmt.Errorf("gateway clients: %w", err)
	}
	if err := adminv1.RegisterUserAdminServiceHandlerServer(ctx, gw, grpcserver.NewUserAdminService(a.userProvider, a.sessionMgr, a.recorder)); err != nil {
		return nil, fmt.Errorf("gateway users: %w", err)
	}
	if err := adminv1.RegisterTokenAdminServiceHandlerServer(ctx, gw, grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
		Sessions:  a.sessionMgr,
		TempStore: a.tempStore,
		Issuers:   a.tokenIssuers,
		Recorder:  a.recorder,
	})); err != nil {
		return nil, fmt.Errorf("gateway tokens: %w", err)
	}
	if err := adminv1.RegisterPermissionAdminServiceHandlerServer(ctx, gw, grpcserver.NewPermissionAdminService(a.provider, a.recorder)); err != nil {
		return nil, fmt.Errorf("gateway permissions: %w", err)
	}
	if a.snapshotPipeline != nil {
		if err := adminv1.RegisterSnapshotAdminServiceHandlerServer(ctx, gw, grpcserver.NewSnapshotAdminService(
			a.snapshotPipeline, a.snapshotStorage, a.snapshotter, a.snapshotRestorer, a.recorder)); err != nil {
			return nil, fmt.Errorf("gateway snapshots: %w", err)
		}
	}
	if a.releaseStore != nil {
		if err := adminv1.RegisterReleaseAdminServiceHandlerServer(ctx, gw, grpcserver.NewReleaseAdminService(
			a.releaseRegistry, a.releaseStore, a.recorder)); err != nil {
			return nil, fmt.Errorf("gateway releases: %w", err)
		}
	}
	if a.tenantStore != nil {
		if err := adminv1.RegisterTenantAdminServiceHandlerServer(ctx, gw, grpcserver.NewTenantAdminService(
			a.tenantStore, a.recorder, a.server.InvalidateTenantSuspensionCache)); err != nil {
			return nil, fmt.Errorf("gateway tenants: %w", err)
		}
	}
	logger.Info("admin REST gateway mounted", "prefix", adminAPIPathPrefix)

	// Outer mux: admin paths go through middleware → gateway; everything
	// else falls through to the SSO runtime handler.
	gated := a.adminMW.HTTPMiddleware(gw)
	mux := http.NewServeMux()
	mux.Handle(adminAPIPathPrefix, gated)
	mux.Handle("/", base)
	return mux, nil
}

// runBootstrap constructs the file-backed Tracker, the AdminSeed bundle,
// and runs every built-in step that hasn't yet been applied. Errors are
// fatal — the operator must succeed at first-boot init before we accept
// any traffic.
func runBootstrap(cfg *config.Config, a *app, logger sso.Logger) error {
	statePath := cfg.Bootstrap.StatePath
	if statePath == "" {
		statePath = "bootstrap.json"
	}
	tracker, err := bootstrapfile.New(statePath)
	if err != nil {
		return fmt.Errorf("tracker: %w", err)
	}
	defer tracker.Close()

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
	if path := cfg.Bootstrap.AdminPasswordFile; path != "" {
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
	}

	// Snapshot restore runs BEFORE the runner so AdvanceBootstrap can
	// bump the Tracker — that lets seed steps already covered by the
	// snapshot skip themselves on the same boot. Restorer.Tracker must
	// be wired here because the tracker isn't constructed until now.
	if cfg.Snapshot.Enabled && cfg.Snapshot.RestoreFrom != "" && a.snapshotPipeline != nil && a.snapshotRestorer != nil {
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
	}

	bootLock, lockCloser, err := buildBootstrapLock(cfg, logger)
	if err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	if lockCloser != nil {
		defer lockCloser()
	}

	opts := []bootstrap.Option{
		bootstrap.WithRecorder(a.recorder),
		bootstrap.WithLogger(bootstrapLogger{logger}),
	}
	if bootLock != nil {
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
	}

	runner := bootstrap.NewRunner(bootstrapNamespace, tracker, opts...)
	runner.Register(builtin.Steps(seed)...)
	logger.Info("bootstrap: applying pending steps", "namespace", bootstrapNamespace, "state_file", statePath)
	return runner.Run(context.Background())
}

// buildBootstrapLock translates BootstrapLockConfig into a concrete
// lock.Lock implementation. Returns (nil, nil, nil) when no
// coordination is requested — Runner falls back to single-replica path.
// The closer (when non-nil) MUST be called after the Runner exits to
// release the etcd client / file handles.
func buildBootstrapLock(cfg *config.Config, logger sso.Logger) (lock.Lock, func(), error) {
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
// buildPairwiseSubjectStore picks the pairwise reverse-lookup
// backend. memory keeps the single-replica story; sqlite shares
// (pairwise → local) so /userinfo + revoke + end_session on any
// replica can resolve any in-flight bearer token.
func buildPairwiseSubjectStore(cfg config.PairwiseSubjectsConfig) (sso.PairwiseSubjectStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return sso.NewMemoryPairwiseSubjectStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("server.pairwise_subjects.sqlite.dsn required when backend=sqlite")
		}
		store, err := sqlitestores.NewPairwiseSubjectStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown server.pairwise_subjects.backend %q", cfg.Backend)
	}
}

// buildAccountLockout picks the lockout backend. memory keeps the
// single-replica defense; sqlite shares the failure counter so an
// attacker rotating across replicas can't stay under each replica's
// local threshold. Policy overrides (MaxFailures / LockoutDuration
// / FailureWindow) are applied identically to both backends.
func buildAccountLockout(cfg config.AccountLockoutConfig) (sso.AccountLockout, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		l := sso.NewMemoryAccountLockout()
		if cfg.MaxFailures > 0 {
			l.MaxFailures = cfg.MaxFailures
		}
		if cfg.LockoutDuration > 0 {
			l.LockoutDuration = cfg.LockoutDuration
		}
		if cfg.FailureWindow > 0 {
			l.FailureWindow = cfg.FailureWindow
		}
		return l, "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("security.account_lockout.sqlite.dsn required when backend=sqlite")
		}
		l, err := sqlitestores.NewAccountLockout(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		if cfg.MaxFailures > 0 {
			l.MaxFailures = cfg.MaxFailures
		}
		if cfg.LockoutDuration > 0 {
			l.LockoutDuration = cfg.LockoutDuration
		}
		if cfg.FailureWindow > 0 {
			l.FailureWindow = cfg.FailureWindow
		}
		return l, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown security.account_lockout.backend %q", cfg.Backend)
	}
}

// buildSubjectClientIndex picks the SubjectClientIndex backend that
// drives OIDC BCL multi-RP fan-out. memory keeps the single-replica
// story; sqlite shares the index so a logout reaching any replica
// fans out to every client a subject has touched cluster-wide.
func buildSubjectClientIndex(cfg config.BCLIndexConfig) (sso.SubjectClientIndex, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return defaultimpl.NewMemorySubjectClientIndex(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("backchannel_logout.index.sqlite.dsn required when backend=sqlite")
		}
		idx, err := sqlitestores.NewSubjectClientIndex(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return idx, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown backchannel_logout.index.backend %q", cfg.Backend)
	}
}

// buildJTIReplayStore picks the JTI replay backend. memory keeps
// the single-replica defense story; sqlite shares the seen-set
// across the cluster so a replay routed to a different replica still
// gets rejected.
func buildJTIReplayStore(cfg config.JTIReplayConfig) (sso.JTIReplayStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return defaultimpl.NewMemoryJTIReplayStore(), "memory (single-replica only)", nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, "", errors.New("security.jti_replay.sqlite.dsn required when backend=sqlite")
		}
		store, err := sqlitestores.NewJTIReplayStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, "", err
		}
		return store, "sqlite (cluster-shared)", nil
	default:
		return nil, "", fmt.Errorf("unknown security.jti_replay.backend %q", cfg.Backend)
	}
}

// buildClientCertExtractor picks the RFC 8705 mTLS extractor backend.
//   - "" / "tls" — DefaultTLSPeerCertExtractor (in-process TLS only)
//   - "header"   — HeaderClientCertExtractor (reverse-proxy edge)
//
// convertClientJWKs maps cmd-config JWK entries to sso.JWK. Drops
// nothing — every parameter the SDK consumes is exposed in YAML.
// appendReadyCheck registers v as a /readyz dependency when it
// implements Ping(ctx). All SQLite-backed stores satisfy this via
// the corresponding sqlite package; memory backends don't, so the
// type assertion silently no-ops for them — exactly the cadence we
// want (no readiness signal from a process-local map). name shows up
// in the /readyz response so operators can tell which dependency
// failed.
func appendReadyCheck(opts []sso.Option, name string, v any) []sso.Option {
	p, ok := v.(interface{ Ping(context.Context) error })
	if !ok {
		return opts
	}
	return append(opts, sso.WithReadyCheck(name, p.Ping))
}

// appendRateLimitReadyChecks registers a /readyz check for the
// policy's Default limiter and every prefix-rule limiter. Memory
// limiters silently no-op (no Ping method); the SQLite limiter
// exposes its database handle here so a wedged cluster-shared
// token-bucket trips /readyz before requests start failing.
//
// Per-prefix check names sanitize the prefix into kebab case so they
// surface readably in the /readyz JSON payload — `/token/revoke`
// becomes `sqlite-ratelimit-token-revoke`. Empty / unrecognized
// prefixes fall back to a positional `rule-N` name so two
// configurations can't collide.
func appendRateLimitReadyChecks(opts []sso.Option, p ratelimit.Policy) []sso.Option {
	opts = appendReadyCheck(opts, "sqlite-ratelimit-default", p.Default)
	for i, rule := range p.Prefixes {
		name := sanitizeReadyCheckSuffix(rule.Prefix)
		if name == "" {
			name = fmt.Sprintf("rule-%d", i)
		}
		opts = appendReadyCheck(opts, "sqlite-ratelimit-"+name, rule.Limiter)
	}
	return opts
}

// sanitizeReadyCheckSuffix turns an arbitrary string into a kebab-
// safe suffix for a ReadyCheck name. Alphanumerics pass through;
// every other rune collapses into a single `-` separator. Used by
// appendRateLimitReadyChecks to derive stable, JSON-payload-friendly
// names from operator-supplied URL prefixes.
func sanitizeReadyCheckSuffix(s string) string {
	var b strings.Builder
	dashOK := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dashOK = true
		default:
			if dashOK {
				b.WriteByte('-')
				dashOK = false
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}

func convertClientJWKs(in []config.ClientJWK) []sso.JWK {
	if len(in) == 0 {
		return nil
	}
	out := make([]sso.JWK, len(in))
	for i, j := range in {
		out[i] = sso.JWK{
			Kty: j.Kty,
			Use: j.Use,
			Alg: j.Alg,
			Kid: j.Kid,
			Crv: j.Crv,
			X:   j.X,
			N:   j.N,
			E:   j.E,
		}
	}
	return out
}

// The second return value is a human-readable mode label suitable
// for the boot log so operators can confirm the wiring matches the
// surrounding network topology.
func buildClientCertExtractor(cfg config.MTLSConfig) (sso.ClientCertExtractor, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "", "tls", "peer":
		return sso.DefaultTLSPeerCertExtractor, "DefaultTLSPeerCertExtractor (in-process TLS termination)", nil
	case "header", "proxy":
		if cfg.Header.Name == "" {
			return nil, "", fmt.Errorf("security.mtls.header.name required when backend=%q", backend)
		}
		enc, err := parseHeaderCertEncoding(cfg.Header.Encoding)
		if err != nil {
			return nil, "", err
		}
		return &sso.HeaderClientCertExtractor{HeaderName: cfg.Header.Name, Encoding: enc}, fmt.Sprintf("HeaderClientCertExtractor (header=%q encoding=%q — TRUST EDGE MUST STRIP HEADER)", cfg.Header.Name, cfg.Header.Encoding), nil
	default:
		return nil, "", fmt.Errorf("security.mtls.backend %q (want tls|header)", cfg.Backend)
	}
}

func parseHeaderCertEncoding(s string) (sso.HeaderCertEncoding, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "url-pem", "urlpem", "url_pem":
		return sso.HeaderCertEncodingURLPEM, nil
	case "pem":
		return sso.HeaderCertEncodingPEM, nil
	case "base64-der", "base64der", "base64_der":
		return sso.HeaderCertEncodingBase64DER, nil
	default:
		return 0, fmt.Errorf("security.mtls.header.encoding %q (want url-pem|pem|base64-der)", s)
	}
}

func buildDPoPNonceProvider(cfg config.DPoPNonceConfig, logger sso.Logger) (sso.DPoPNonceProvider, error) {
	if cfg.KeyFile != "" {
		raw, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		// Trim any trailing whitespace/newline the operator likely
		// included when echo-ing the key.
		trimmed := strings.TrimSpace(string(raw))
		// Prefer hex when the file looks like hex; otherwise treat
		// as raw bytes. Hex is easier to inspect + copy.
		if key, err := hex.DecodeString(trimmed); err == nil && len(key) >= 16 {
			return sso.NewHMACNonceProviderWithKey(key, cfg.TTL)
		}
		return sso.NewHMACNonceProviderWithKey([]byte(trimmed), cfg.TTL)
	}
	logger.Info("dpop nonce: no key_file configured — generating process-local key (NOT safe for multi-replica)")
	return sso.NewHMACNonceProvider(cfg.TTL)
}

// buildClientStore / buildUserProvider pick the identity-domain
// backend. Memory keeps the simple-bootstrap story; SQLite persists
// DCR registrations + password users across restarts. Same DSN can
// be shared with OAuth.SQLite — SQLite OS-file-lock handles
// cross-pool coordination.
func buildClientStore(cfg config.IdentityConfig) (sso.ClientStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryClientStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("identity.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewClientStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown identity.backend %q", cfg.Backend)
	}
}

func buildUserProvider(cfg config.IdentityConfig) (sso.UserProvider, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryUserProvider(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("identity.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewUserProvider(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown identity.backend %q", cfg.Backend)
	}
}

// buildSessionManager picks the SessionManager backend. Same memory|
// sqlite selector as the rest of identity-domain stores so operators
// running TokenStrategySession across multiple replicas get cross-
// replica session redemption against a shared SQLite file.
func buildSessionManager(cfg config.IdentityConfig, ttl time.Duration) (sso.SessionManager, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemorySessionManager(ttl), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("identity.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewSessionManager(cfg.SQLite.DSN, ttl)
	default:
		return nil, fmt.Errorf("unknown identity.backend %q", cfg.Backend)
	}
}

// buildAuthCodeStore / buildRefreshTokenStore / buildDeviceCodeStore
// pick between memory + sqlite per cfg.Backend. SQLite needs a DSN;
// memory needs nothing. Each SQLite call opens its own connection
// pool — for SQLite that's fine (OS-level file lock coordinates),
// for a future shared *sql.DB across stores a different abstraction
// is needed.
func buildAuthCodeStore(cfg config.OAuthConfig) (sso.AuthCodeStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryAuthCodeStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewAuthCodeStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q", cfg.Backend)
	}
}

func buildRefreshTokenStore(cfg config.OAuthConfig) (sso.RefreshTokenStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryRefreshTokenStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewRefreshTokenStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q", cfg.Backend)
	}
}

func buildDeviceCodeStore(cfg config.OAuthConfig) (sso.DeviceCodeStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryDeviceCodeStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewDeviceCodeStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q", cfg.Backend)
	}
}

func buildPARStore(cfg config.OAuthConfig) (sso.PARStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryPARStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewPARStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q", cfg.Backend)
	}
}

// resolvePairwiseSalt reads the pairwise hash salt with the same
// file-wins-over-inline precedence the PII redactor uses. Empty
// salt falls back to sso.DefaultPairwiseSalt — fine for tests, not
// fine for production (publicly known).
func resolvePairwiseSalt(cfg config.PairwiseSubjectsConfig) (string, error) {
	if cfg.SaltFile != "" {
		b, err := os.ReadFile(cfg.SaltFile)
		if err != nil {
			return "", fmt.Errorf("read salt file: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return cfg.Salt, nil
}

// resolvePIISalt reads the redaction salt from inline YAML or a file
// (file wins when both set — operators typically use file for prod).
// Returns an error when both are empty so a misconfiguration becomes
// loud at boot rather than silently degrading to an empty salt that
// makes hash inversion trivial.
func resolvePIISalt(cfg config.AuditPIIRedactionConfig) (string, error) {
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

// buildRateLimitPolicy translates RateLimitConfig into a ratelimit.Policy.
// Each prefix becomes its own Limiter (sized by per_sec + burst);
// Default kicks in for paths no prefix matches. A zero DefaultPerSec
// leaves Default nil (no limit on unmatched paths — useful when only
// a few hot endpoints need throttling). KeyByClientIDOrIP is used so
// HTTP-Basic-authenticated /token traffic buckets per-client, with
// IP as the fallback for unauthenticated paths.
//
// Backend choice:
//   - "" / "memory" — per-replica MemoryLimiter (default).
//   - "sqlite" — SQLiteLimiter against cfg.SQLite.DSN; each prefix
//     gets a distinct bucket_name so multiple rules can share one
//     DSN file without colliding.
func buildRateLimitPolicy(cfg config.RateLimitConfig) (ratelimit.Policy, error) {
	p := ratelimit.Policy{Key: ratelimit.KeyByClientIDOrIP}
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "", "memory":
		if cfg.DefaultPerSec > 0 {
			p.Default = ratelimit.NewMemoryLimiter(cfg.DefaultPerSec, cfg.DefaultBurst)
		}
		for _, r := range cfg.Prefixes {
			p.Prefixes = append(p.Prefixes, ratelimit.PrefixRule{
				Prefix:  r.Prefix,
				Limiter: ratelimit.NewMemoryLimiter(r.PerSec, r.Burst),
			})
		}
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return ratelimit.Policy{}, errors.New("security.rate_limit.sqlite.dsn required when backend=sqlite")
		}
		if cfg.DefaultPerSec > 0 {
			lim, err := ratelimit.NewSQLiteLimiter(cfg.SQLite.DSN, cfg.DefaultPerSec, cfg.DefaultBurst, "default")
			if err != nil {
				return ratelimit.Policy{}, fmt.Errorf("rate_limit default sqlite: %w", err)
			}
			p.Default = lim
		}
		for _, r := range cfg.Prefixes {
			lim, err := ratelimit.NewSQLiteLimiter(cfg.SQLite.DSN, r.PerSec, r.Burst, r.Prefix)
			if err != nil {
				return ratelimit.Policy{}, fmt.Errorf("rate_limit prefix %q sqlite: %w", r.Prefix, err)
			}
			p.Prefixes = append(p.Prefixes, ratelimit.PrefixRule{
				Prefix:  r.Prefix,
				Limiter: lim,
			})
		}
	default:
		return ratelimit.Policy{}, fmt.Errorf("unknown security.rate_limit.backend %q", cfg.Backend)
	}
	return p, nil
}

// buildRegistry materializes the service registry for cmd.
//
// Memory backend is per-process (no peer discovery, no TTL); etcd
// is cluster-shared via lease + KeepAlive. The etcd path is
// constructed here so the etcd transitive dep stays out of the
// registry SPI. Returns the kind ("memory" or "etcd") so caller
// can decide whether a /readyz check is meaningful (memory has no
// backend state to probe).
func buildRegistry(cfg *config.RegistryConfig, logger sso.Logger) (registry.Registry, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "", "memory":
		logger.Info("service registry", "backend", "memory")
		return memory.New(), "memory", nil
	case "etcd":
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, "", errors.New("registry.etcd_endpoints required when registry.backend=etcd")
		}
		reg, err := registryetcd.New(registryetcd.Config{
			Endpoints:   cfg.EtcdEndpoints,
			Prefix:      cfg.EtcdPrefix,
			DialTimeout: cfg.EtcdDialTimeout,
			Username:    cfg.EtcdUsername,
			Password:    cfg.EtcdPassword,
		})
		if err != nil {
			return nil, "", fmt.Errorf("registry/etcd: %w", err)
		}
		logger.Info("service registry",
			"backend", "etcd",
			"endpoints", cfg.EtcdEndpoints,
			"prefix", cfg.EtcdPrefix)
		return reg, "etcd", nil
	default:
		return nil, "", fmt.Errorf("unknown registry.backend %q", cfg.Backend)
	}
}

// resolveServiceID derives the registry Service.ID. Explicit YAML
// wins; otherwise we synthesize from the issuer + the host's short
// hostname so two replicas of the same issuer don't write the same
// etcd key and clobber each other's lease. Hostname lookup failure
// falls back to a fixed suffix — better stable-ish than panic.
func resolveServiceID(explicit, issuer string) string {
	if id := strings.TrimSpace(explicit); id != "" {
		return id
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		return issuer + "-1"
	}
	if idx := strings.IndexByte(host, '.'); idx > 0 {
		host = host[:idx]
	}
	return issuer + "-" + host
}

// buildRiskScorer materializes the reference rule-based
// [defaultimpl.RuleBasedRiskScorer] from RiskConfig. Returns nil
// when risk.enabled=false so cmd skips WithRiskScorer entirely
// (zero overhead on the login path).
//
// Operators with richer risk requirements (impossible-travel,
// device fingerprinting, ML scoring) should fork cmd and call
// sso.WithRiskScorer with their own implementation — the
// RuleBasedRiskScorer is the declarative 80% case, not a
// framework for embedding richer policies.
func buildRiskScorer(cfg *config.RiskConfig, logger sso.Logger) (sso.RiskScorer, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	scorer, err := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{
		IPDenyList:       cfg.IPDenyList,
		IPAllowList:      cfg.IPAllowList,
		CountryDenyList:  cfg.CountryDenyList,
		CountryAllowList: cfg.CountryAllowList,
		DenyOnGeoMissing: cfg.DenyOnGeoMissing,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("risk scorer enabled (rule-based)",
		"ip_deny", len(cfg.IPDenyList),
		"ip_allow", len(cfg.IPAllowList),
		"country_deny", len(cfg.CountryDenyList),
		"country_allow", len(cfg.CountryAllowList),
		"deny_on_geo_missing", cfg.DenyOnGeoMissing)
	return scorer, nil
}

// buildMFA materializes the MFA orchestration triple: provider, store,
// per-challenge TTL. Returns (nil, nil, 0, "", nil) when MFA is
// disabled so cmd skips WithMFAProvider / WithMFAChallengeStore entirely
// — RequireMFA then decays to Allow (back-compat).
//
// totpAuth is the *authenticators.TOTPAuthenticator instance built in
// buildAuthenticators; webauthnHelper is the *webauthn.Helper built
// earlier in the assembly path. Passing the same instances here means
// each factor's secret/credential store + policy is single-source
// between primary auth and MFA step-up — one enrollment, two
// consumer roles.
//
// The returned mode string is a short backend identifier emitted in
// the startup log + suitable for /readyz wiring suffixes.
func buildMFA(cfg config.MFAConfig, totpAuth *authenticators.TOTPAuthenticator, webauthnHelper *webauthn.Helper, logger sso.Logger) (sso.MFAProvider, sso.MFAChallengeStore, time.Duration, string, *sqlitestores.PushApprovalStore, error) {
	if !cfg.Enabled {
		return nil, nil, 0, "", nil, nil
	}

	// Provider: "totp" and "webauthn" carry YAML toggles. "multi"
	// composes several leaf kinds via MultiMFAProvider. Other factors
	// (push, IdP redirect, hardware OTP) ship in the SDK and embedders
	// wire them via WithMFAProvider directly, so this switch
	// intentionally stays narrow.
	kind := strings.ToLower(strings.TrimSpace(cfg.Provider.Kind))
	if kind == "" {
		kind = "totp"
	}
	capture := &pushStoreCapture{}
	provider, err := buildMFAProviderByKind(kind, cfg.Provider.Kinds, cfg.Provider.Push, totpAuth, webauthnHelper, logger, capture)
	if err != nil {
		return nil, nil, 0, "", nil, err
	}

	// Challenge store: memory for single-replica, sqlite for clusters.
	// Same backend-selection pattern AccountLockout / SubjectClientIndex
	// use; the schema gets migrated at construction so no separate
	// boot step is required.
	backend := strings.ToLower(strings.TrimSpace(cfg.Challenge.Backend))
	var (
		store     sso.MFAChallengeStore
		storeKind string
	)
	switch backend {
	case "", "memory":
		store = defaultimpl.NewMemoryMFAChallengeStore()
		storeKind = "memory (single-replica only)"
	case "sqlite":
		if cfg.Challenge.SQLite.DSN == "" {
			return nil, nil, 0, "", nil, errors.New("mfa.challenge.sqlite.dsn required when backend=sqlite")
		}
		s, err := sqlitestores.NewMFAChallengeStore(cfg.Challenge.SQLite.DSN)
		if err != nil {
			return nil, nil, 0, "", nil, err
		}
		store = s
		storeKind = "sqlite (cluster-shared)"
	default:
		return nil, nil, 0, "", nil, fmt.Errorf("unknown mfa.challenge.backend %q (supported: memory, sqlite)", backend)
	}

	logger.Info("mfa orchestration enabled",
		"provider", kind,
		"methods", provider.SupportedMethods(),
		"store", storeKind,
		"ttl", cfg.Challenge.TTL)

	return provider, store, cfg.Challenge.TTL, storeKind, capture.store, nil
}

// buildMFAProviderByKind constructs the MFA provider tree for the
// requested kind. Recursive for kind=multi (one level only — nested
// multi is rejected to keep the operator surface flat). Leaf kinds
// (totp, webauthn, push) fail loud when their underlying
// dependency is nil / misconfigured.
//
// outerKinds is the cfg.Provider.Kinds slice — used only when
// kind=multi to list the inner leaf kinds. Empty or single-entry
// Kinds when kind=multi → error (a multi with zero or one inner
// provider is a misconfiguration; use the leaf kind directly).
// pushStoreCapture is buildMFAProviderByKind's side-channel for
// surfacing the SQLite PushApprovalStore handle through the
// recursive multi-build. cmd's buildMFA inspects the capture's
// handle to register a /readyz check + launch the PruneExpired
// loop. Memory-backed push or absent push both leave the field
// nil.
type pushStoreCapture struct {
	store *sqlitestores.PushApprovalStore
}

func buildMFAProviderByKind(kind string, outerKinds []string, pushCfg config.MFAPushConfig, totpAuth *authenticators.TOTPAuthenticator, webauthnHelper *webauthn.Helper, logger sso.Logger, capture *pushStoreCapture) (sso.MFAProvider, error) {
	switch kind {
	case "totp":
		if totpAuth == nil {
			return nil, errors.New("mfa.provider.kind=totp requires authenticators.totp.enabled=true")
		}
		return authenticators.NewTOTPMFAProvider(totpAuth), nil
	case "webauthn":
		if webauthnHelper == nil {
			return nil, errors.New("mfa.provider.kind=webauthn requires webauthn.enabled=true")
		}
		p, err := webauthn.NewWebAuthnMFAProvider(webauthnHelper)
		if err != nil {
			return nil, fmt.Errorf("mfa.provider.kind=webauthn: %w", err)
		}
		return p, nil
	case "push":
		provider, sqliteStore, err := buildPushMFAProvider(pushCfg, logger)
		if err != nil {
			return nil, err
		}
		if capture != nil {
			capture.store = sqliteStore
		}
		return provider, nil
	case "multi":
		if len(outerKinds) < 2 {
			return nil, errors.New("mfa.provider.kind=multi requires at least two entries in mfa.provider.kinds")
		}
		seen := make(map[string]struct{}, len(outerKinds))
		innerProviders := make([]sso.MFAProvider, 0, len(outerKinds))
		for _, inner := range outerKinds {
			innerKind := strings.ToLower(strings.TrimSpace(inner))
			if innerKind == "" {
				return nil, errors.New("mfa.provider.kinds contains an empty entry")
			}
			if innerKind == "multi" {
				return nil, errors.New("mfa.provider.kinds cannot contain 'multi' (no nesting)")
			}
			if _, dup := seen[innerKind]; dup {
				return nil, fmt.Errorf("mfa.provider.kinds duplicate entry %q", innerKind)
			}
			seen[innerKind] = struct{}{}
			p, err := buildMFAProviderByKind(innerKind, nil, pushCfg, totpAuth, webauthnHelper, logger, capture)
			if err != nil {
				return nil, fmt.Errorf("mfa.provider.kinds[%s]: %w", innerKind, err)
			}
			innerProviders = append(innerProviders, p)
		}
		return defaultimpl.NewMultiMFAProvider(innerProviders...)
	default:
		return nil, fmt.Errorf("unknown mfa.provider.kind %q (supported: totp, webauthn, push, multi)", kind)
	}
}

// buildPushMFAProvider wires the reference push MFA factor —
// PushApprovalStore backend + PushTransport selection + pollInterval
// + maxWait. Today the only ship-included transport is the
// log-only stub (mirrors the cmd SMS/email "stub" pattern); operators
// fork cmd to drop in FCM/APNs/webhook. The reference impl is
// useful for development + smoke-test deployments.
//
// Returns the provider plus the SQLite store handle (or nil if
// backend=memory). cmd uses the typed handle for /readyz wiring +
// the optional PruneExpired loop. Error path: nil/nil/<err> when
// backend / transport / SQLite validation fails — kind=push is a
// misconfig if any of those components are absent.
func buildPushMFAProvider(cfg config.MFAPushConfig, logger sso.Logger) (sso.MFAProvider, *sqlitestores.PushApprovalStore, error) {
	// Backend: memory for single-replica; sqlite for cluster.
	var (
		store       defaultimpl.PushApprovalStore
		sqliteStore *sqlitestores.PushApprovalStore
	)
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "", "memory":
		store = defaultimpl.NewMemoryPushApprovalStore()
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, nil, errors.New("mfa.provider.push.sqlite.dsn required when backend=sqlite")
		}
		s, err := sqlitestores.NewPushApprovalStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, nil, fmt.Errorf("mfa.provider.push.sqlite: %w", err)
		}
		store = s
		sqliteStore = s
	default:
		return nil, nil, fmt.Errorf("unknown mfa.provider.push.backend %q (supported: memory, sqlite)", backend)
	}

	// Transport: log only (operators fork for real push delivery).
	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if transport == "" {
		transport = "log"
	}
	var pushTransport defaultimpl.PushTransport
	switch transport {
	case "log":
		pushTransport = defaultimpl.PushTransportFunc(func(_ context.Context, id, subject string, _ map[string]string) error {
			logger.Info("push approval delivered (log-only transport — fork cmd for real push)",
				"approval_id", id, "subject", subject)
			return nil
		})
	default:
		return nil, nil, fmt.Errorf("unknown mfa.provider.push.transport %q (supported: log)", transport)
	}

	var opts []defaultimpl.PushMFAOption
	if cfg.PollInterval > 0 {
		opts = append(opts, defaultimpl.WithPushPollInterval(cfg.PollInterval))
	}
	if cfg.MaxWait > 0 {
		opts = append(opts, defaultimpl.WithPushMaxWait(cfg.MaxWait))
	}
	provider, err := defaultimpl.NewPushMFAProvider(store, pushTransport, opts...)
	if err != nil {
		return nil, nil, err
	}
	return provider, sqliteStore, nil
}

// buildNetworkStore materializes the netpolicy.Store for cmd.
//
// Memory backend defers to [config.Config.BuildNetworkStore] (which
// applies seeds itself). The etcd backend is constructed here so the
// config package keeps the etcd transitive dep out of its SPI; seeds
// flow through [config.ApplyNetworkPolicySeeds] so both paths share
// identical seed semantics + error wrapping.
//
// Returns (nil, "", nil) when network is disabled. The returned kind
// is "memory" or "etcd"; cmd uses it to decide whether to register a
// /readyz check (memory has no backend health signal to report).
func buildNetworkStore(cfg *config.NetworkConfig, logger sso.Logger) (netpolicy.Store, string, error) {
	if !cfg.Enabled {
		return nil, "", nil
	}
	backend := strings.ToLower(strings.TrimSpace(cfg.Store))
	switch backend {
	case "", "memory":
		store, err := (&config.Config{Network: *cfg}).BuildNetworkStore()
		if err != nil {
			return nil, "", err
		}
		logger.Info("network policy store", "backend", "memory", "seed_policies", len(cfg.Policies))
		return store, "memory", nil
	case "etcd":
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, "", errors.New("network.etcd_endpoints required when network.store=etcd")
		}
		store, err := netpolicyetcd.New(netpolicyetcd.Config{
			Endpoints:   cfg.EtcdEndpoints,
			Prefix:      cfg.EtcdPrefix,
			DialTimeout: cfg.EtcdDialTimeout,
			Username:    cfg.EtcdUsername,
			Password:    cfg.EtcdPassword,
		})
		if err != nil {
			return nil, "", fmt.Errorf("netpolicy/etcd: %w", err)
		}
		if err := config.ApplyNetworkPolicySeeds(context.Background(), store, cfg.Policies); err != nil {
			_ = store.Close()
			return nil, "", err
		}
		logger.Info("network policy store",
			"backend", "etcd",
			"endpoints", cfg.EtcdEndpoints,
			"prefix", cfg.EtcdPrefix,
			"seed_policies", len(cfg.Policies))
		return store, "etcd", nil
	default:
		return nil, "", fmt.Errorf("unknown network.store %q", cfg.Store)
	}
}

// buildSnapshotSubsystem materializes the snapshot Pipeline + Storage from
// SnapshotConfig. Returns (nil, nil, nil) when snapshot.enabled=false. The
// Snapshotter / Restorer that depend on the runtime stores are wired
// separately inside buildApp once those stores exist.
func buildSnapshotSubsystem(cfg *config.Config, logger sso.Logger) (*snapshot.Pipeline, snapshot.Storage, error) {
	if !cfg.Snapshot.Enabled {
		return nil, nil, nil
	}
	var store snapshot.Storage
	switch strings.ToLower(cfg.Snapshot.Storage.Backend) {
	case "", "file":
		dir := cfg.Snapshot.Storage.File.Dir
		if dir == "" {
			dir = "./snapshots"
		}
		s, err := storagefile.New(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("snapshot file storage: %w", err)
		}
		logger.Info("snapshot storage: file", "dir", dir)
		store = s
	case "inline":
		logger.Info("snapshot storage: inline (in-memory)")
		store = storageinline.New()
	default:
		return nil, nil, fmt.Errorf("unknown snapshot.storage.backend %q", cfg.Snapshot.Storage.Backend)
	}

	var sealer snapshot.Sealer
	switch strings.ToLower(cfg.Snapshot.Encryption.Backend) {
	case "", "none":
		sealer = encryptionnone.New()
	case "passphrase":
		pass := cfg.Snapshot.Encryption.Passphrase
		if pass == "" && cfg.Snapshot.Encryption.PassphraseFile != "" {
			b, err := os.ReadFile(cfg.Snapshot.Encryption.PassphraseFile)
			if err != nil {
				return nil, nil, fmt.Errorf("snapshot passphrase file: %w", err)
			}
			pass = strings.TrimRight(string(b), "\r\n")
		}
		if pass == "" {
			return nil, nil, errors.New("snapshot.encryption.backend=passphrase requires passphrase or passphrase_file")
		}
		sealer = encryptionpass.NewFromString(pass)
		logger.Info("snapshot encryption: passphrase (argon2id+chacha20poly1305)")
	default:
		return nil, nil, fmt.Errorf("unknown snapshot.encryption.backend %q", cfg.Snapshot.Encryption.Backend)
	}

	return &snapshot.Pipeline{Sealer: sealer}, store, nil
}

// buildReleaseSubsystem materialises the releases.ReleaseStore +
// Pinner + Registry from ReleasesConfig. Returns (nil, nil, nil)
// when releases.enabled=false.
func buildReleaseSubsystem(cfg *config.Config, logger sso.Logger) (*releases.Registry, releases.ReleaseStore, error) {
	if !cfg.Releases.Enabled {
		return nil, nil, nil
	}
	var store releases.ReleaseStore
	switch strings.ToLower(cfg.Releases.Store.Backend) {
	case "", "file":
		dir := cfg.Releases.Store.File.Dir
		if dir == "" {
			dir = "./releases"
		}
		s, err := releasefile.New(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("release file store: %w", err)
		}
		logger.Info("release store: file", "dir", dir)
		store = s
	case "memory":
		logger.Info("release store: memory (in-process)")
		store = releasememory.New()
	default:
		return nil, nil, fmt.Errorf("unknown releases.store.backend %q", cfg.Releases.Store.Backend)
	}

	var pinner releases.Pinner
	switch strings.ToLower(cfg.Releases.Pinner.Backend) {
	case "", "noop":
		pinner = releasenoop.Pinner{Logger: logger.Info}
		logger.Info("release pinner: noop")
	case "static":
		dir := cfg.Releases.Pinner.Static.BundleDir
		if dir == "" {
			return nil, nil, errors.New("releases.pinner.backend=static requires releases.pinner.static.bundle_dir")
		}
		p, err := releasestatic.New(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("release static pinner: %w", err)
		}
		logger.Info("release pinner: static", "bundle_dir", dir)
		pinner = p
	case "docker":
		dir := cfg.Releases.Pinner.Docker.BundleDir
		if dir == "" {
			return nil, nil, errors.New("releases.pinner.backend=docker requires releases.pinner.docker.bundle_dir")
		}
		p, err := releasedocker.New(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("release docker pinner: %w", err)
		}
		if c := cfg.Releases.Pinner.Docker.Cmd; c != "" {
			p.Cmd = c
		}
		logger.Info("release pinner: docker", "bundle_dir", dir, "cmd", p.Cmd)
		pinner = p
	default:
		return nil, nil, fmt.Errorf("unknown releases.pinner.backend %q", cfg.Releases.Pinner.Backend)
	}

	var probe releases.HealthProbe
	switch strings.ToLower(cfg.Releases.Probe.Backend) {
	case "":
		// no probe; forward Pin always succeeds even if the new release is unhealthy
	case "http":
		url := cfg.Releases.Probe.HTTP.URL
		if url == "" {
			return nil, nil, errors.New("releases.probe.backend=http requires releases.probe.http.url")
		}
		probe = releasehttpprobe.New(url)
		logger.Info("release probe: http", "url", url)
	default:
		return nil, nil, fmt.Errorf("unknown releases.probe.backend %q", cfg.Releases.Probe.Backend)
	}

	return &releases.Registry{
		Store:        store,
		Pinner:       pinner,
		Probe:        probe,
		ProbePolls:   cfg.Releases.Probe.Polls,
		ProbeBackoff: cfg.Releases.Probe.Backoff,
	}, store, nil
}

// snapshotRestorerAdapter bridges releases.SnapshotRestorer onto the
// snapshot.Pipeline + snapshot.Storage + snapshot.Restorer trio.
// Lives in the cmd binary so the releases package stays free of any
// snapshot import — keeping the two SDKs independently evolvable.
type snapshotRestorerAdapter struct {
	pipeline *snapshot.Pipeline
	storage  snapshot.Storage
	restorer *snapshot.Restorer
}

func (a *snapshotRestorerAdapter) RestoreByID(ctx context.Context, snapshotID string) error {
	if a.pipeline == nil || a.storage == nil || a.restorer == nil {
		return fmt.Errorf("snapshot subsystem not configured")
	}
	snap, err := a.pipeline.Load(ctx, a.storage, snapshotID)
	if err != nil {
		return fmt.Errorf("load snapshot %q: %w", snapshotID, err)
	}
	// AdvanceBootstrap=false because rollback shouldn't move the
	// bootstrap high-water mark — that's a one-way ratchet for
	// first-boot init, not a release-flip mechanism.
	if _, err := a.restorer.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeOverwrite}); err != nil {
		return fmt.Errorf("restore snapshot %q: %w", snapshotID, err)
	}
	return nil
}

// buildTenantStore materialises the tenant.Store from TenantConfig
// and seeds any declared tenants + domains. Returns (nil, nil)
// when tenant.enabled=false so cmd can pass the result to
// sso.WithTenantStore unconditionally (the option no-ops on nil).
func buildTenantStore(cfg *config.Config, logger sso.Logger) (tenant.Store, error) {
	if !cfg.Tenant.Enabled {
		return nil, nil
	}
	var store tenant.Store
	switch strings.ToLower(cfg.Tenant.Backend) {
	case "", "memory":
		store = tenantmemory.New()
		logger.Info("tenant store: memory (in-process)")
	default:
		return nil, fmt.Errorf("unknown tenant.backend %q", cfg.Tenant.Backend)
	}

	ctx := context.Background()
	for _, t := range cfg.Tenant.Tenants {
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
			_ = store.Close()
			return nil, fmt.Errorf("seed tenant %q: %w", t.ID, err)
		}
	}
	for _, d := range cfg.Tenant.Domains {
		if err := store.PutDomain(ctx, &tenant.Domain{
			Hostname:        d.Hostname,
			TenantID:        d.TenantID,
			DefaultClientID: d.DefaultClientID,
			IsApex:          d.IsApex,
			Branding:        d.Branding,
		}); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("seed domain %q: %w", d.Hostname, err)
		}
	}
	logger.Info("tenant seed complete",
		"tenants", len(cfg.Tenant.Tenants),
		"domains", len(cfg.Tenant.Domains))
	return store, nil
}

// buildGeoProvider materialises the geo.Provider from GeoConfig.
// Returns nil when geo.enabled=false so cmd can pass the result to
// sso.WithGeoProvider unconditionally (the option no-ops on nil).
func buildGeoProvider(cfg *config.Config, logger sso.Logger) (geo.Provider, error) {
	if !cfg.Geo.Enabled {
		return nil, nil
	}
	switch strings.ToLower(cfg.Geo.Backend) {
	case "", "static":
		p := geostatic.New()
		for _, e := range cfg.Geo.Static.Entries {
			if err := p.Add(e.CIDR, geo.GeoInfo{
				CountryCode:         e.CountryCode,
				Region:              e.Region,
				City:                e.City,
				TimeZone:            e.TimeZone,
				RecommendedLanguage: e.RecommendedLanguage,
			}); err != nil {
				return nil, fmt.Errorf("geo static entry %q: %w", e.CIDR, err)
			}
		}
		logger.Info("geo provider: static", "entries", p.Len())
		return p, nil
	default:
		return nil, fmt.Errorf("unknown geo.backend %q", cfg.Geo.Backend)
	}
}

// bootstrapLogger adapts sso.Logger to bootstrap.Logger (Info/Error pair).
type bootstrapLogger struct{ inner sso.Logger }

func (b bootstrapLogger) Info(msg string, kv ...any)  { b.inner.Info(msg, kv...) }
func (b bootstrapLogger) Error(msg string, kv ...any) { b.inner.Error(msg, kv...) }

// buildApp wires every SDK component the config asks for and returns them
// as a bundle so HTTP and gRPC entrypoints can share instances.
func buildApp(cfg *config.Config, logger sso.Logger) (*app, error) {
	clientStore, err := buildClientStore(cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("identity client_store: %w", err)
	}
	for _, c := range cfg.Clients {
		seeded := &sso.Client{
			ID:                               c.ID,
			Secret:                           c.Secret,
			Name:                             c.Name,
			RedirectURIs:                     c.RedirectURIs,
			AllowedScopes:                    c.AllowedScopes,
			AllowedAuthenticators:            c.AllowedAuthenticators,
			TokenStrategy:                    c.TokenStrategy,
			Active:                           c.Active,
			TenantID:                         c.TenantID,
			RequirePKCE:                      c.RequirePKCE,
			AllowedResources:                 c.AllowedResources,
			PostLogoutRedirectURIs:           c.PostLogoutRedirectURIs,
			AllowedAuthorizationDetailsTypes: c.AllowedAuthorizationDetailsTypes,
			RefreshTokenTTL:                  c.RefreshTokenTTL,
			AccessTokenTTL:                   c.AccessTokenTTL,
			AllowedPKCEMethods:               c.AllowedPKCEMethods,
			RequireSignedRequestObject:       c.RequireSignedRequestObject,
			RequirePAR:                       c.RequirePAR,
			AllowedRequestURIs:               c.AllowedRequestURIs,
			DeviceCodeTTL:                    c.DeviceCodeTTL,
			DeviceCodePollInterval:           c.DeviceCodePollInterval,
			UserinfoSignedResponseAlg:        c.UserinfoSignedResponseAlg,
			BackchannelLogoutURI:             c.BackchannelLogoutURI,
			SubjectType:                      c.SubjectType,
			SectorIdentifierURI:              c.SectorIdentifierURI,
			FrontchannelLogoutURI:            c.FrontchannelLogoutURI,
			JWKS:                             convertClientJWKs(c.JWKS),
		}
		if err := clientStore.Add(context.Background(), seeded); err != nil && !errors.Is(err, sso.ErrClientExists) {
			return nil, fmt.Errorf("seed client %q: %w", c.ID, err)
		}
	}

	userProvider, err := buildUserProvider(cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("identity user_provider: %w", err)
	}
	sessionMgr, err := buildSessionManager(cfg.Identity, cfg.Server.SessionTTL)
	if err != nil {
		return nil, fmt.Errorf("identity session_manager: %w", err)
	}
	jwtIssuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(cfg.Server.Issuer),
		defaultimpl.WithEd25519TokenTTL(cfg.Server.TokenTTL),
		defaultimpl.WithEd25519MaxClockSkew(cfg.Server.MaxClockSkew),
	)
	sessionIssuer := defaultimpl.NewSessionTokenIssuer(
		defaultimpl.WithSessionTokenTTL(cfg.Server.SessionTTL),
	)
	tokenIssuers := map[string]sso.TokenIssuer{
		sso.TokenStrategyJWT:     jwtIssuer,
		sso.TokenStrategySession: sessionIssuer,
	}

	opts := append(cfg.ServerOptions(),
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithLogger(logger),
		sso.WithTracingMiddleware(),   // legacy request-id middleware (not OTel)
		sso.WithTracing("sso-server"), // OTel HTTP-span middleware; no-op until tracing.Init activates
		sso.WithTokenIssuer(sso.TokenStrategyJWT, jwtIssuer),
		sso.WithTokenIssuer(sso.TokenStrategySession, sessionIssuer),
		sso.WithUserProvider(userProvider),
		sso.WithClientStore(clientStore),
		sso.WithSessionManager(sessionMgr),
		// Ed25519JWTIssuer satisfies sso.IDTokenIssuer — sharing one
		// signing key keeps JWKS single-entry. Without this option the
		// id_token field is omitted from every /token + /auth/login
		// response and OIDC is silently disabled, which is the wrong
		// default for a binary called "sso-server".
		sso.WithIDTokenIssuer(jwtIssuer),
	)
	opts = appendReadyCheck(opts, "sqlite-identity-clients", clientStore)
	opts = appendReadyCheck(opts, "sqlite-identity-users", userProvider)
	opts = appendReadyCheck(opts, "sqlite-identity-sessions", sessionMgr)

	var recorder *audit.Recorder
	var asyncSink *audit.AsyncSink
	var auditRetentionCancel context.CancelFunc
	var auditRetentionDone <-chan struct{}
	if cfg.Audit.Enabled {
		primary, primaryName, err := buildPrimaryAuditSink(cfg.Audit, logger)
		if err != nil {
			return nil, fmt.Errorf("audit: build primary sink: %w", err)
		}
		// Retention scheduler runs against the SQLite primary sink
		// (the in-memory ring buffer self-prunes by capacity). cmd
		// type-asserts the concrete *auditsqlite.Sink; the in-memory
		// path silently skips so operators flipping retention.enabled
		// don't need to coordinate with the backend choice.
		if rc := cfg.Audit.Retention; rc.Enabled && primaryName == "sqlite" {
			sqliteSink, ok := primary.(*auditsqlite.Sink)
			if !ok {
				return nil, errors.New("audit.retention.enabled requires audit.backend=sqlite (assert failed — internal bug)")
			}
			if rc.MaxAge <= 0 {
				return nil, errors.New("audit.retention.max_age required when retention.enabled")
			}
			interval := rc.Interval
			if interval <= 0 {
				interval = time.Hour
			}
			retentionCtx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			auditRetentionCancel = cancel
			auditRetentionDone = done
			go runAuditRetention(retentionCtx, done, sqliteSink, interval, rc.MaxAge, logger)
			logger.Info("audit: retention scheduler enabled",
				"max_age", rc.MaxAge, "interval", interval)
		}
		var sink audit.Sink = primary
		// Webhook fan-out wraps the primary sink so in-process /audit
		// query reads still see every event. Wrapped in RetryingSink
		// so transient collector failures don't drop events; combined
		// via MultiSink for fan-out. AGENTS.md compose order:
		// AsyncSink(MultiSink(Primary, RetryingSink(WebhookSink))).
		if w := cfg.Audit.Webhook; w.Enabled {
			if w.URL == "" {
				return nil, errors.New("audit.webhook.url required when audit.webhook.enabled")
			}
			webhookOpts := []audit.WebhookOption{}
			if w.Timeout > 0 {
				webhookOpts = append(webhookOpts, audit.WithWebhookTimeout(w.Timeout))
			}
			for k, v := range w.Headers {
				webhookOpts = append(webhookOpts, audit.WithWebhookHeader(k, v))
			}
			webhook := audit.NewWebhookSink(w.URL, webhookOpts...)
			retryOpts := []audit.RetryOption{}
			if w.Retry.MaxAttempts > 0 {
				retryOpts = append(retryOpts, audit.WithRetryMaxAttempts(w.Retry.MaxAttempts))
			}
			if w.Retry.InitialBackoff > 0 {
				retryOpts = append(retryOpts, audit.WithRetryInitialBackoff(w.Retry.InitialBackoff))
			}
			if w.Retry.MaxBackoff > 0 {
				retryOpts = append(retryOpts, audit.WithRetryMaxBackoff(w.Retry.MaxBackoff))
			}
			retrying := audit.NewRetryingSink(webhook, retryOpts...)
			sink = audit.NewMultiSink(primary, retrying)
			logger.Info("audit: webhook fan-out enabled",
				"url", w.URL,
				"max_attempts", w.Retry.MaxAttempts,
				"header_count", len(w.Headers),
			)
		}
		// Async wrap when configured. The buffered hot path keeps slow
		// (e.g. webhook) sinks from blocking request latency. Memory
		// sink benefits little — the wrap is opt-in per operator.
		if cfg.Audit.Async.Enabled {
			asyncOpts := []audit.AsyncOption{
				audit.WithAsyncDropHandler(func(_ *audit.Event, err error) {
					logger.Error("audit async drop", "error", err)
				}),
			}
			if n := cfg.Audit.Async.BufferSize; n > 0 {
				asyncOpts = append(asyncOpts, audit.WithAsyncBuffer(n))
			}
			if n := cfg.Audit.Async.Workers; n > 0 {
				asyncOpts = append(asyncOpts, audit.WithAsyncWorkers(n))
			}
			if ms := cfg.Audit.Async.RecordTimeoutMs; ms > 0 {
				asyncOpts = append(asyncOpts, audit.WithAsyncRecordTimeout(time.Duration(ms)*time.Millisecond))
			}
			asyncSink = audit.NewAsyncSink(sink, asyncOpts...)
			asyncSink.Start()
			sink = asyncSink
		}
		recorderOpts := []audit.Option{
			audit.WithErrorHandler(func(err error) { logger.Error("audit sink", "error", err) }),
		}
		if pii := cfg.Audit.PIIRedaction; pii.Enabled {
			salt, err := resolvePIISalt(pii)
			if err != nil {
				return nil, fmt.Errorf("audit pii_redaction salt: %w", err)
			}
			recorderOpts = append(recorderOpts, audit.WithRedactor(audit.DefaultPIIRedactor(salt)))
			logger.Info("audit: pii redaction enabled (actor hashed, ip truncated, user-agent stripped)")
		}
		if cfg.Audit.HashChain {
			recorderOpts = append(recorderOpts, audit.WithHashChain())
			logger.Info("audit: hash chain enabled — Events carry PrevHash + Hash for tamper-evidence")
		}
		recorder = audit.New(sink, recorderOpts...)
		opts = append(opts, sso.WithAuditRecorder(recorder))
		if cfg.Audit.APIEnabled {
			opts = append(opts, sso.WithAuditAPI())
		}
		// Register a readycheck for the primary sink if it satisfies
		// the Ping interface — the SQLite sink does; MemorySink
		// silently no-ops.
		opts = appendReadyCheck(opts, "audit-"+primaryName, primary)
	}

	var provider permissions.Provider
	if p := cfg.BuildPermissionProvider(); p != nil {
		provider = p
		opts = append(opts, sso.WithPermissionProvider(provider))
		if cfg.Permissions.EmbedInLogin {
			opts = append(opts, sso.WithEmbedPermissionsInLogin())
		}
	}
	// Admin needs a non-nil permission provider for scope checks. Mint a
	// memory provider so first-boot bootstrap can seed into something.
	if cfg.Admin.Enabled && provider == nil {
		mp := permissions.NewMemoryProvider()
		provider = mp
		opts = append(opts, sso.WithPermissionProvider(provider))
	}

	netStore, netStoreKind, err := buildNetworkStore(&cfg.Network, logger)
	if err != nil {
		return nil, fmt.Errorf("network policy store: %w", err)
	}
	var classifier *netpolicy.Classifier
	var netStop <-chan struct{}
	if netStore != nil {
		classifier = netpolicy.NewClassifier()
		done, err := classifier.Start(context.Background(), netStore)
		if err != nil {
			_ = netStore.Close()
			return nil, fmt.Errorf("network classifier: %w", err)
		}
		netStop = done
		opts = append(opts, sso.WithNetworkPolicy(netStore, classifier))
		if cfg.Network.APIEnabled {
			opts = append(opts, sso.WithNetworkPolicyAPI())
		}
		if netStoreKind == "etcd" {
			opts = appendReadyCheck(opts, "etcd-netpolicy", netStore)
		}
	}

	auths, tempStore, totpAuth := buildAuthenticators(cfg, logger)
	for _, ath := range auths {
		opts = append(opts, sso.WithAuthenticator(ath))
	}

	geoProvider, err := buildGeoProvider(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("geo provider: %w", err)
	}
	if geoProvider != nil {
		opts = append(opts, sso.WithGeoProvider(geoProvider))
		if cfg.Geo.LookupTimeout > 0 {
			opts = append(opts, sso.WithGeoMiddlewareOptions(sso.GeoMiddlewareOptions{
				Timeout: cfg.Geo.LookupTimeout,
			}))
		}
	}

	// Risk scorer wired AFTER geo so country-based rules see the
	// populated GeoInfo on RiskRequest.Geo. When risk.enabled is
	// false, buildRiskScorer returns nil and cmd skips
	// WithRiskScorer entirely — zero overhead on /auth/login.
	riskScorer, err := buildRiskScorer(&cfg.Risk, logger)
	if err != nil {
		return nil, fmt.Errorf("risk scorer: %w", err)
	}
	if riskScorer != nil {
		opts = append(opts, sso.WithRiskScorer(riskScorer))
	}

	// WebAuthn helper built here (before MFA so mfa.provider.kind=
	// webauthn can wrap the same helper instance, sharing UserStore +
	// SessionStore + RP config across primary auth and step-up). Same
	// /readyz wiring as the other SQLite-substrate components.
	webauthnHelper, webauthnUsers, webauthnSessions, err := buildWebAuthnHelper(cfg.WebAuthn, logger)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	opts = appendReadyCheck(opts, "sqlite-webauthn-users", webauthnUsers)
	opts = appendReadyCheck(opts, "sqlite-webauthn-sessions", webauthnSessions)

	// MFA orchestration wired AFTER the risk scorer so the wire-up
	// order matches the runtime gating order (Risk emits
	// DecisionRequireMFA → MFA orchestration consumes it). Without
	// both Provider + Store opts, RequireMFA decays to Allow — same
	// back-compat fall-through embedders see when they ship a Risk
	// scorer ahead of MFA.
	mfaProvider, mfaStore, mfaTTL, _, pushApprovalStore, err := buildMFA(cfg.MFA, totpAuth, webauthnHelper, logger)
	if err != nil {
		return nil, fmt.Errorf("mfa: %w", err)
	}
	if mfaProvider != nil && mfaStore != nil {
		opts = append(opts, sso.WithMFAProvider(mfaProvider))
		opts = append(opts, sso.WithMFAChallengeStore(mfaStore, mfaTTL))
		opts = appendReadyCheck(opts, "sqlite-mfa-challenges", mfaStore)
	}
	// When push MFA wired with SQLite backend, surface the store
	// handle for /readyz wiring + the optional PruneExpired loop
	// (operators wanting bounded approval-table growth without
	// running external cron).
	if pushApprovalStore != nil {
		opts = appendReadyCheck(opts, "sqlite-push-approvals", pushApprovalStore)
	}

	tenantStore, err := buildTenantStore(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("tenant store: %w", err)
	}
	if tenantStore != nil {
		opts = append(opts, sso.WithTenantStore(tenantStore))
		if cfg.Tenant.LookupTimeout > 0 || cfg.Tenant.IncludeSuspended {
			opts = append(opts, sso.WithTenantMiddlewareOptions(sso.TenantMiddlewareOptions{
				Timeout:          cfg.Tenant.LookupTimeout,
				IncludeSuspended: cfg.Tenant.IncludeSuspended,
			}))
		}
		if cfg.Tenant.SuspensionCheck.Enabled {
			opts = append(opts, sso.WithTenantSuspensionCheck(cfg.Tenant.SuspensionCheck.CacheTTL))
		}
	}
	if cfg.Server.DiscoveryDocCacheTTL != 0 {
		// Negative TTL also passes through — the SDK treats <= 0 as
		// "disable body cache" so operators can flip caching off
		// from config without removing the field entirely.
		opts = append(opts, sso.WithDiscoveryDocCacheTTL(cfg.Server.DiscoveryDocCacheTTL))
	}
	if cfg.Server.DiscoveryCacheTTL != 0 {
		opts = append(opts, sso.WithDiscoveryCacheTTL(cfg.Server.DiscoveryCacheTTL))
	}
	if cfg.Server.JWKSCacheTTL != 0 {
		opts = append(opts, sso.WithJWKSCacheTTL(cfg.Server.JWKSCacheTTL))
	}
	if cfg.Security.DPoPNonce.Enabled {
		provider, err := buildDPoPNonceProvider(cfg.Security.DPoPNonce, logger)
		if err != nil {
			return nil, fmt.Errorf("dpop nonce provider: %w", err)
		}
		opts = append(opts, sso.WithDPoPNonceProvider(provider))
	}
	if cfg.OAuth.AuthCode.Enabled {
		store, err := buildAuthCodeStore(cfg.OAuth)
		if err != nil {
			return nil, fmt.Errorf("oauth.auth_code: %w", err)
		}
		opts = append(opts, sso.WithAuthCodeStore(store, cfg.OAuth.AuthCode.TTL))
		opts = appendReadyCheck(opts, "sqlite-oauth-auth-codes", store)
	}
	var refreshTokenStore sso.RefreshTokenStore
	var refreshTokenTTL time.Duration
	if cfg.OAuth.RefreshToken.Enabled {
		store, err := buildRefreshTokenStore(cfg.OAuth)
		if err != nil {
			return nil, fmt.Errorf("oauth.refresh_token: %w", err)
		}
		opts = append(opts, sso.WithRefreshTokenStore(store, cfg.OAuth.RefreshToken.TTL))
		opts = appendReadyCheck(opts, "sqlite-oauth-refresh-tokens", store)
		refreshTokenStore = store
		refreshTokenTTL = cfg.OAuth.RefreshToken.TTL
	}
	if cfg.OAuth.DeviceCode.Enabled {
		store, err := buildDeviceCodeStore(cfg.OAuth)
		if err != nil {
			return nil, fmt.Errorf("oauth.device_code: %w", err)
		}
		opts = append(opts, sso.WithDeviceCodeStore(
			store,
			cfg.OAuth.DeviceCode.TTL,
			cfg.OAuth.DeviceCode.PollInterval,
			cfg.OAuth.DeviceCode.VerificationBaseURL,
		))
		opts = appendReadyCheck(opts, "sqlite-oauth-device-codes", store)
	}
	if cfg.OAuth.PAR.Enabled {
		store, err := buildPARStore(cfg.OAuth)
		if err != nil {
			return nil, fmt.Errorf("par store: %w", err)
		}
		opts = append(opts, sso.WithPARStore(store, cfg.OAuth.PAR.TTL))
		opts = appendReadyCheck(opts, "sqlite-oauth-par", store)
	}
	if jar := cfg.OAuth.JAR; jar.Enabled {
		f := sso.NewHTTPJARFetcher()
		if jar.Timeout > 0 {
			f.Client.Timeout = jar.Timeout
		}
		if jar.MaxBytes > 0 {
			f.MaxBytes = jar.MaxBytes
		}
		opts = append(opts, sso.WithJARFetcher(f))
	}
	if cr := cfg.ClientRegistration; cr.Enabled {
		opts = append(opts, sso.WithDynamicClientRegistration(sso.DCRPolicy{
			InitialAccessToken:    cr.InitialAccessToken,
			AllowOpenRegistration: cr.AllowOpenRegistration,
			DefaultActive:         cr.DefaultActive,
			DefaultTokenStrategy:  cr.DefaultTokenStrategy,
			AllowedAuthenticators: cr.AllowedAuthenticators,
		}))
		if cr.AllowOpenRegistration && cr.InitialAccessToken == "" {
			logger.Info("client_registration: OPEN — no initial_access_token; production deployments SHOULD restrict")
		}
	}
	if cfg.BackchannelLogout.Enabled {
		idx, mode, err := buildSubjectClientIndex(cfg.BackchannelLogout.Index)
		if err != nil {
			return nil, fmt.Errorf("subject_client_index: %w", err)
		}
		opts = append(opts,
			sso.WithBackchannelLogout(jwtIssuer, sso.NewHTTPLogoutNotifier()),
			sso.WithSubjectClientIndex(idx),
		)
		opts = appendReadyCheck(opts, "sqlite-bcl-subject-client-index", idx)
		if n := cfg.BackchannelLogout.MaxConcurrent; n > 0 {
			opts = append(opts, sso.WithBackchannelLogoutMaxConcurrent(n))
		}
		logger.Info("backchannel logout: enabled", "subject_client_index", mode)
	}
	if cfg.Server.OAuth21StrictMode {
		opts = append(opts, sso.WithOAuth21StrictMode(true))
		logger.Info("oauth2.1 strict mode: implicit grant disabled, S256-only PKCE, PKCE required for every login")
	}
	if cfg.Server.PairwiseSubjects.Enabled {
		salt, err := resolvePairwiseSalt(cfg.Server.PairwiseSubjects)
		if err != nil {
			return nil, fmt.Errorf("pairwise_subjects salt: %w", err)
		}
		store, mode, err := buildPairwiseSubjectStore(cfg.Server.PairwiseSubjects)
		if err != nil {
			return nil, fmt.Errorf("pairwise_subjects store: %w", err)
		}
		opts = append(opts,
			sso.WithPairwiseSubjectStore(store),
			sso.WithPairwiseSalt(salt),
		)
		opts = appendReadyCheck(opts, "sqlite-pairwise-subjects", store)
		logger.Info("oidc pairwise subjects: enabled", "store", mode)
	}
	if len(cfg.Server.SupportedACRValues) > 0 {
		opts = append(opts, sso.WithSupportedACRValues(cfg.Server.SupportedACRValues...))
	}
	if om := cfg.Server.OperatorMetadata; om.PolicyURI != "" || om.TosURI != "" || om.ServiceDocumentation != "" {
		opts = append(opts, sso.WithOperatorMetadata(om.PolicyURI, om.TosURI, om.ServiceDocumentation))
	}
	if cfg.Server.SignedMetadata {
		// jwtIssuer satisfies sso.MetadataSigner — reuse the same
		// signing key as access + id + userinfo so JWKS continues to
		// cover everything with one entry.
		if signer, ok := any(jwtIssuer).(sso.MetadataSigner); ok {
			opts = append(opts, sso.WithMetadataSigner(signer))
		} else {
			logger.Info("signed_metadata enabled but the configured JWT issuer does not implement MetadataSigner — discovery doc will not be signed")
		}
	}
	if cfg.Metrics.Enabled {
		m := metrics.New()
		// When the audit async wrapper is active, expose its drop
		// counters + queue gauges on the same registry so a single
		// scrape job covers HTTP + auth + audit-backpressure signals.
		if asyncSink != nil {
			m.Registry.MustRegister(metrics.NewAsyncSinkCollector(asyncSink))
		}
		opts = append(opts, sso.WithMetrics(m))
		logger.Info("metrics: prometheus /metrics enabled")
	}
	if n := cfg.Security.BodyLimit.MaxBytes; n > 0 {
		opts = append(opts, sso.WithBodyLimit(n))
		logger.Info("security: body limit", "max_bytes", n)
	}
	for _, ov := range cfg.Security.BodyLimit.Overrides {
		if ov.Prefix == "" {
			continue
		}
		opts = append(opts, sso.WithBodyLimitForPath(ov.Prefix, ov.MaxBytes))
		logger.Info("security: body limit override", "prefix", ov.Prefix, "max_bytes", ov.MaxBytes)
	}
	if rl := cfg.Security.RateLimit; rl.Enabled {
		policy, err := buildRateLimitPolicy(rl)
		if err != nil {
			return nil, fmt.Errorf("rate limit policy: %w", err)
		}
		opts = append(opts, sso.WithRateLimit(policy))
		opts = appendRateLimitReadyChecks(opts, policy)
		backend := rl.Backend
		if backend == "" {
			backend = "memory"
		}
		logger.Info("security: rate limit enabled",
			"backend", backend,
			"default_per_sec", rl.DefaultPerSec,
			"default_burst", rl.DefaultBurst,
			"prefix_rules", len(rl.Prefixes))
	}
	if cfg.Security.JTIReplay.Enabled {
		store, mode, err := buildJTIReplayStore(cfg.Security.JTIReplay)
		if err != nil {
			return nil, fmt.Errorf("jti replay store: %w", err)
		}
		opts = append(opts, sso.WithJTIReplayStore(store))
		opts = appendReadyCheck(opts, "sqlite-jti-replay", store)
		logger.Info("security: jti replay protection enabled", "backend", mode)
	}
	if cfg.Security.MTLS.Enabled {
		extractor, mode, err := buildClientCertExtractor(cfg.Security.MTLS)
		if err != nil {
			return nil, fmt.Errorf("mtls extractor: %w", err)
		}
		opts = append(opts, sso.WithClientCertExtractor(extractor))
		logger.Info("security: mTLS bound tokens enabled", "extractor", mode)
	}
	if al := cfg.Security.AccountLockout; al.Enabled {
		lockout, mode, err := buildAccountLockout(al)
		if err != nil {
			return nil, fmt.Errorf("account lockout: %w", err)
		}
		opts = append(opts, sso.WithAccountLockout(lockout))
		opts = appendReadyCheck(opts, "sqlite-account-lockout", lockout)
		logger.Info("security: account lockout enabled",
			"backend", mode,
			"max_failures", al.MaxFailures,
			"lockout_duration", al.LockoutDuration,
			"failure_window", al.FailureWindow)
	}
	if c := cfg.Security.CORS; c.Enabled && len(c.AllowedOrigins) > 0 {
		opts = append(opts, sso.WithCORS(cors.Policy{
			AllowedOrigins:   c.AllowedOrigins,
			AllowedMethods:   c.AllowedMethods,
			AllowedHeaders:   c.AllowedHeaders,
			ExposedHeaders:   c.ExposedHeaders,
			AllowCredentials: c.AllowCredentials,
			MaxAge:           c.MaxAge,
		}))
		logger.Info("security: cors enabled", "allowed_origins", c.AllowedOrigins)
	}

	// Service registry built before NewServer so its etcd Ping can
	// participate in /readyz alongside the SQLite peers. Self-
	// registration happens later (needs cfg.Server.Listen resolved).
	reg, regKind, err := buildRegistry(&cfg.Registry, logger)
	if err != nil {
		return nil, fmt.Errorf("service registry: %w", err)
	}
	if regKind == "etcd" {
		opts = appendReadyCheck(opts, "etcd-registry", reg)
	}

	srv := sso.NewServer(opts...)

	var adminMW *sso.AdminMiddleware
	if cfg.Admin.Enabled {
		adminMW = sso.NewAdminMiddleware(srv, provider)
	}

	pipeline, snapStorage, err := buildSnapshotSubsystem(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("snapshot subsystem: %w", err)
	}
	var snapshotter *snapshot.Snapshotter
	var restorer *snapshot.Restorer
	if pipeline != nil {
		snapshotter = &snapshot.Snapshotter{
			Clients:     clientStore,
			Users:       userProvider,
			Permissions: provider,
			NetPolicy:   netStore,
			Namespace:   bootstrapNamespace,
		}
		restorer = &snapshot.Restorer{
			Clients:     clientStore,
			Users:       userProvider,
			Permissions: provider,
			NetPolicy:   netStore,
			Namespace:   bootstrapNamespace,
		}
	}

	releaseRegistry, releaseStore, err := buildReleaseSubsystem(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("release subsystem: %w", err)
	}
	var snapshotRetentionCancel context.CancelFunc
	var snapshotRetentionDone <-chan struct{}
	if rc := cfg.Snapshot.Retention; rc.Enabled {
		if pipeline == nil || snapStorage == nil {
			return nil, errors.New("snapshot.retention.enabled requires snapshot.enabled=true")
		}
		if rc.Keep <= 0 {
			return nil, errors.New("snapshot.retention.keep must be > 0 (set 0 disables; use enabled=false to skip the loop)")
		}
		interval := rc.Interval
		if interval <= 0 {
			interval = 6 * time.Hour
		}
		retentionCtx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		snapshotRetentionCancel = cancel
		snapshotRetentionDone = done
		go runSnapshotRetention(retentionCtx, done, snapStorage, interval, rc.Keep, logger)
		logger.Info("snapshot: retention scheduler enabled",
			"keep", rc.Keep, "interval", interval)
	}

	// Wire ConfigSnapshot-aware Rollback when both subsystems are
	// enabled and the operator opted in. Done here (after both
	// factories) so the Registry receives a fully-formed adapter
	// with the runtime restorer/pipeline already in scope.
	if releaseRegistry != nil && pipeline != nil && cfg.Releases.SnapshotIntegration {
		releaseRegistry.SnapshotRestorer = &snapshotRestorerAdapter{
			pipeline: pipeline,
			storage:  snapStorage,
			restorer: restorer,
		}
		logger.Info("release rollback wired with snapshot restore")
	}

	addr := strings.TrimSpace(cfg.Registry.ServiceAddress)
	if addr == "" {
		addr = cfg.Server.Listen
		if addr == "" || addr[0] == ':' {
			addr = "127.0.0.1" + addr
		}
	}
	tags := cfg.Registry.ServiceTags
	if len(tags) == 0 {
		tags = []string{"sso"}
	}
	// ServiceTTL only matters under etcd (lease lifetime + KeepAlive
	// cadence). Memory ignores it; the registration's lifetime IS the
	// process lifetime. Default to 30s so dead etcd-backed replicas
	// fall off the discovery list within one TTL window.
	ttl := cfg.Registry.ServiceTTL
	if regKind == "etcd" && ttl <= 0 {
		ttl = 30 * time.Second
	}
	if err := reg.Register(context.Background(), &registry.Service{
		ID:      resolveServiceID(cfg.Registry.ServiceID, cfg.Server.Issuer),
		Name:    "sso",
		Address: addr,
		Tags:    tags,
		TTL:     ttl,
	}); err != nil {
		return nil, fmt.Errorf("registry register: %w", err)
	}
	return &app{
		server:                  srv,
		recorder:                recorder,
		provider:                provider,
		registry:                reg,
		netStore:                netStore,
		classifier:              classifier,
		clientStore:             clientStore,
		userProvider:            userProvider,
		sessionMgr:              sessionMgr,
		tempStore:               tempStore,
		tokenIssuers:            tokenIssuers,
		idTokenIssuer:           jwtIssuer,
		refreshTokenStore:       refreshTokenStore,
		refreshTokenTTL:         refreshTokenTTL,
		adminMW:                 adminMW,
		snapshotPipeline:        pipeline,
		snapshotStorage:         snapStorage,
		snapshotter:             snapshotter,
		snapshotRestorer:        restorer,
		releaseRegistry:         releaseRegistry,
		releaseStore:            releaseStore,
		tenantStore:             tenantStore,
		webauthnHelper:          webauthnHelper,
		auditAsyncSink:          asyncSink,
		auditRetentionCancel:    auditRetentionCancel,
		auditRetentionDone:      auditRetentionDone,
		snapshotRetentionCancel: snapshotRetentionCancel,
		snapshotRetentionDone:   snapshotRetentionDone,
		netStop:                 netStop,
	}, nil
}

// runSnapshotRetention is the background loop cmd launches when
// snapshot.retention.enabled wires it. Same shutdown contract as
// runAuditRetention (close done channel on exit). First prune
// fires after the first interval, not immediately.
//
// PruneOldest errors don't tear down the loop — a transient
// storage outage shouldn't suspend retention forever; the loop
// logs + waits for the next tick.
func runSnapshotRetention(ctx context.Context, done chan<- struct{}, storage snapshot.Storage, interval time.Duration, keep int, logger sso.Logger) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := snapshot.PruneOldest(ctx, storage, keep)
			if err != nil {
				logger.Error("snapshot retention prune failed", "error", err, "keep", keep)
				continue
			}
			if len(deleted) > 0 {
				logger.Info("snapshot retention pruned envelopes",
					"deleted_count", len(deleted), "keep", keep)
			}
		}
	}
}

// runAuditRetention is the background loop cmd launches when
// audit.retention.enabled wires it. Wakes every interval (after
// the first interval — not at start so short-lived deploys don't
// trigger expensive bulk deletes during boot), calls
// auditsqlite.Sink.Prune(ctx, now-maxAge), logs the result.
//
// Exits on ctx cancellation (cmd shutdown). Closes done channel
// on exit so cmd's Shutdown can bound the wait.
//
// Prune errors are logged but don't stop the loop — a transient
// SQLite contention shouldn't tear down retention forever.
func runAuditRetention(ctx context.Context, done chan<- struct{}, sink *auditsqlite.Sink, interval, maxAge time.Duration, logger sso.Logger) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-maxAge)
			deleted, err := sink.Prune(ctx, cutoff)
			if err != nil {
				logger.Error("audit retention prune failed", "error", err, "cutoff", cutoff)
				continue
			}
			if deleted > 0 {
				logger.Info("audit retention pruned events",
					"deleted", deleted, "cutoff", cutoff)
			}
		}
	}
}

// buildPrimaryAuditSink constructs the [audit.Sink] cmd places at
// the root of the sink composition (the one /audit query reads from
// + that gets wrapped by MultiSink+Webhook+Async). Backend selects
// between in-process MemorySink and the SQLite-backed Sink. Returns
// the sink + a short identifier used as the ReadyCheck suffix.
func buildPrimaryAuditSink(cfg config.AuditConfig, logger sso.Logger) (audit.Sink, string, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		logger.Info("audit: primary sink", "backend", "memory", "capacity", cfg.MemoryCapacity)
		return audit.NewMemorySink(cfg.MemoryCapacity), "memory", nil
	case "sqlite":
		if cfg.Sqlite.DSN == "" {
			return nil, "", errors.New("audit.sqlite.dsn required when audit.backend=sqlite")
		}
		sink, err := auditsqlite.New(cfg.Sqlite.DSN)
		if err != nil {
			return nil, "", fmt.Errorf("open sqlite audit sink: %w", err)
		}
		logger.Info("audit: primary sink", "backend", "sqlite", "dsn", cfg.Sqlite.DSN)
		return sink, "sqlite", nil
	default:
		return nil, "", fmt.Errorf("audit.backend must be one of memory|sqlite, got %q", cfg.Backend)
	}
}

// loadSecretFile reads a secret material file and returns the content
// with a trailing newline (if any) stripped. Empty contents fail so
// operators see the misconfiguration at boot rather than shipping
// with an authenticator that admits the empty string as a credential.
// Matches the file-based secret pattern bootstrap.admin_password_file
// uses — keeps secrets out of YAML where readers + version control
// would expose them.
func loadSecretFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	s := strings.TrimRight(string(raw), "\r\n")
	if s == "" {
		return "", fmt.Errorf("%s: empty secret", path)
	}
	return s, nil
}

// loadEd25519PublicKeyPEM reads a PEM file containing a "PUBLIC KEY"
// block and returns the parsed Ed25519 key. Refuses any other key
// type to keep operators from accidentally feeding RSA/ECDSA pubkeys
// that the verifier would silently reject at signature time.
func loadEd25519PublicKeyPEM(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s: PEM type %q; want PUBLIC KEY", path, block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pub key in %s: %w", path, err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: parsed key is %T; want ed25519.PublicKey", path, parsed)
	}
	return pub, nil
}

// loadCertPool reads one or more PEM files and returns an x509.CertPool
// containing every CERTIFICATE block found across them. Empty paths
// list returns an empty (but non-nil) pool — the certificate
// authenticator refuses to validate against an empty trust store anyway,
// so the caller can surface that as a config error if it cares.
//
// A single bad file (missing, unparseable, no PEM blocks) fails the
// whole load so operators see the misconfiguration at boot instead of
// silently shipping with a partial trust store that admits some
// expected certs but rejects others.
func loadCertPool(paths []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, p := range paths {
		if p == "" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		appended := 0
		rest := raw
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse cert in %s: %w", p, err)
			}
			pool.AddCert(cert)
			appended++
		}
		if appended == 0 {
			return nil, fmt.Errorf("%s: no CERTIFICATE PEM blocks found", p)
		}
	}
	return pool, nil
}

// passwordSeed stores one cmd-side username->bcrypt-hash entry.
type passwordSeed struct {
	hash      []byte
	subjectID string
}

// buildBcryptPasswordVerifier returns a PasswordVerifier closed over
// an in-memory username->bcrypt-hash map seeded from YAML. Bad
// entries (missing field, unreadable file, malformed hash) log + skip
// at boot rather than crashing; an empty map yields a verifier that
// rejects every credential.
//
// Unknown-username and wrong-password paths both run one bcrypt
// compare so wall-clock response time can't enumerate the seed
// list. The dummy hash is generated at verifier-build time at the
// cost of the FIRST loaded seed (or bcrypt.DefaultCost when no
// seeds are present), so the dummy and real-hash bcrypt compares
// sit in the same order of magnitude — without that, an attacker
// could split "real cost-10 user" from "dummy cost-12 unknown user"
// by latency.
func buildBcryptPasswordVerifier(users []config.PasswordUserConfig, logger sso.Logger) (authenticators.PasswordVerifier, int) {
	seeds := make(map[string]passwordSeed, len(users))
	dummyCost := bcrypt.DefaultCost
	seeded := 0
	for _, u := range users {
		if u.Username == "" || u.BcryptHashFile == "" || u.SubjectID == "" {
			logger.Error("password seed skipped (missing field)",
				"username", u.Username, "subject_id", u.SubjectID)
			continue
		}
		hash, err := loadBcryptHashFile(u.BcryptHashFile)
		if err != nil {
			logger.Error("password seed skipped (load hash)",
				"username", u.Username, "file", u.BcryptHashFile, "error", err)
			continue
		}
		if seeded == 0 {
			if c, err := bcrypt.Cost(hash); err == nil {
				dummyCost = c
			}
		}
		seeds[u.Username] = passwordSeed{hash: hash, subjectID: u.SubjectID}
		seeded++
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte("dummy-for-timing-equalization-only"), dummyCost)
	if err != nil {
		panic(fmt.Sprintf("bcrypt dummy hash gen: %v", err))
	}
	verifier := authenticators.PasswordVerifierFunc(func(_ context.Context, user, pass string) (*sso.AuthResult, error) {
		entry, ok := seeds[user]
		hash := dummy
		if ok {
			hash = entry.hash
		}
		// Run bcrypt unconditionally so unknown-user and wrong-password
		// take the same wall-clock time. The error is collapsed to a
		// single string regardless of which branch failed.
		if err := bcrypt.CompareHashAndPassword(hash, []byte(pass)); err != nil || !ok {
			return nil, errors.New("password: invalid credentials")
		}
		return &sso.AuthResult{UserID: entry.subjectID, ExternalID: user}, nil
	})
	return verifier, seeded
}

// loadBcryptHashFile reads a bcrypt hash from disk. The file's first
// line (newline-stripped) is the hash. Refuses anything that doesn't
// start with the bcrypt format prefix so a misconfigured file
// (plaintext password, sha256 hash, accidentally swapped file) fails
// at boot rather than producing an authenticator that silently never
// matches.
func loadBcryptHashFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// Bcrypt hashes are single-line ASCII; tolerate trailing newline
	// from `echo` and strip any leading/trailing whitespace from
	// hand-edited files. Reject internal newlines to catch the
	// "wrote the wrong file" case.
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, fmt.Errorf("%s: empty file", path)
	}
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("%s: multi-line content; expected a single bcrypt hash", path)
	}
	if !strings.HasPrefix(s, "$2a$") && !strings.HasPrefix(s, "$2b$") && !strings.HasPrefix(s, "$2y$") {
		return nil, fmt.Errorf("%s: not a bcrypt hash (must start with $2a$/$2b$/$2y$)", path)
	}
	return []byte(s), nil
}

// buildAuthenticators returns the configured authenticators, the temp
// token store (when wired), and the *TOTPAuthenticator handle (when
// TOTP is enabled). Both ancillary returns are separated so admin /
// MFA wiring downstream can reuse the same backing instances —
// admin TokenAdminService issues against the temp store; MFA
// orchestration wraps the TOTP authenticator with TOTPMFAProvider so
// step-up and primary auth share one secret store + skew policy.
// Both return nil when the corresponding authenticator is disabled.
func buildAuthenticators(cfg *config.Config, logger sso.Logger) ([]sso.Authenticator, authenticators.TempTokenStore, *authenticators.TOTPAuthenticator) {
	var auths []sso.Authenticator
	var tempStore authenticators.TempTokenStore
	var totpAuth *authenticators.TOTPAuthenticator
	codeStore := authenticators.NewMemoryCodeStore()

	if a := cfg.Authenticators.Password; a != nil && a.Enabled {
		verifier, seeded := buildBcryptPasswordVerifier(a.Users, logger)
		auths = append(auths, authenticators.NewPasswordAuthenticator(verifier))
		logger.Info("password authenticator enabled", "seeded_users", seeded)
	}

	if a := cfg.Authenticators.Phone; a != nil && a.Enabled {
		auths = append(auths, authenticators.NewPhoneAuthenticator(
			codeStore,
			authenticators.SMSSenderFunc(func(_ context.Context, phone, code string) error {
				logger.Info("sms stub", "phone", phone, "code", code)
				return nil
			}),
			authenticators.WithPhoneCodeLength(a.CodeLength),
			authenticators.WithPhoneCodeTTL(a.CodeTTL),
		))
	}

	if a := cfg.Authenticators.Email; a != nil && a.Enabled {
		auths = append(auths, authenticators.NewEmailAuthenticator(
			codeStore,
			authenticators.EmailSenderFunc(func(_ context.Context, email, code string) error {
				logger.Info("email stub", "email", email, "code", code)
				return nil
			}),
			authenticators.WithEmailCodeLength(a.CodeLength),
			authenticators.WithEmailCodeTTL(a.CodeTTL),
		))
	}

	if a := cfg.Authenticators.TempToken; a != nil && a.Enabled {
		tempStore = authenticators.NewMemoryTempTokenStore()
		auths = append(auths, authenticators.NewTempTokenAuthenticator(tempStore, a.TTL))
	}

	if a := cfg.Authenticators.KeyPair; a != nil && a.Enabled {
		store := authenticators.NewMemoryPublicKeyStore()
		seeded := 0
		for _, k := range a.PublicKeys {
			if k.KeyID == "" || k.PublicKeyFile == "" || k.SubjectID == "" {
				logger.Error("keypair seed skipped (missing field)",
					"key_id", k.KeyID, "subject_id", k.SubjectID)
				continue
			}
			pub, err := loadEd25519PublicKeyPEM(k.PublicKeyFile)
			if err != nil {
				logger.Error("keypair seed skipped (load pub key)",
					"key_id", k.KeyID, "file", k.PublicKeyFile, "error", err)
				continue
			}
			store.Register(k.KeyID, pub, &sso.Subject{ID: k.SubjectID})
			seeded++
		}
		auths = append(auths, authenticators.NewKeyPairAuthenticator(store, a.MaxClockSkew))
		logger.Info("keypair authenticator enabled", "seeded_keys", seeded)
	}

	if a := cfg.Authenticators.APIKey; a != nil && a.Enabled {
		store := authenticators.NewMemoryAPIKeyStore()
		seeded := 0
		for _, k := range a.Keys {
			if k.KeyID == "" || k.SecretFile == "" || k.SubjectID == "" {
				logger.Error("apikey seed skipped (missing field)",
					"key_id", k.KeyID, "subject_id", k.SubjectID)
				continue
			}
			secret, err := loadSecretFile(k.SecretFile)
			if err != nil {
				logger.Error("apikey seed skipped (load secret)",
					"key_id", k.KeyID, "file", k.SecretFile, "error", err)
				continue
			}
			store.Register(k.KeyID, secret, &sso.Subject{ID: k.SubjectID})
			seeded++
		}
		auths = append(auths, authenticators.NewAPIKeyAuthenticator(store))
		logger.Info("apikey authenticator enabled", "seeded_keys", seeded)
	}

	if a := cfg.Authenticators.Certificate; a != nil && a.Enabled {
		roots, err := loadCertPool(a.TrustedCAFiles)
		if err != nil {
			logger.Error("certificate authenticator skipped (trusted_ca_files)", "error", err)
		} else {
			var certOpts []authenticators.CertOption
			if len(a.IntermediateFiles) > 0 {
				inter, err := loadCertPool(a.IntermediateFiles)
				if err != nil {
					logger.Error("certificate authenticator: intermediate_files", "error", err)
				} else {
					certOpts = append(certOpts, authenticators.WithCertIntermediates(inter))
				}
			}
			auths = append(auths, authenticators.NewCertificateAuthenticator(roots, certOpts...))
			logger.Info("certificate authenticator enabled",
				"trusted_cas", len(a.TrustedCAFiles),
				"intermediates", len(a.IntermediateFiles))
		}
	}

	if a := cfg.Authenticators.TOTP; a != nil && a.Enabled {
		// MemoryTOTPStore is the dev / demo tier — secrets are
		// MUST-encrypt material in production, so operators with
		// durable needs should fork cmd and supply their own
		// TOTPStore implementation. Leaving the store empty here
		// means /auth/login?provider=totp returns a generic
		// "invalid code" until enrollment populates a secret.
		var totpOpts []authenticators.TOTPOption
		if a.SkewSteps > 0 {
			totpOpts = append(totpOpts, authenticators.WithTOTPSkew(a.SkewSteps))
		}
		// Held as a typed handle so buildMFA can wrap this exact
		// instance with TOTPMFAProvider — one secret store, two
		// consumer roles (primary auth + step-up MFA).
		totpAuth = authenticators.NewTOTPAuthenticator(
			authenticators.NewMemoryTOTPStore(), totpOpts...,
		)
		auths = append(auths, totpAuth)
		logger.Info("totp authenticator enabled (memory store; supply your own TOTPStore for production)")
	}

	for _, fed := range cfg.Authenticators.OIDCFederation {
		if fed == nil {
			continue
		}
		auth, err := authenticators.NewOIDCFederationAuthenticator(authenticators.OIDCFederationConfig{
			Name:                  fed.Name,
			AuthorizationEndpoint: fed.AuthorizationEndpoint,
			TokenEndpoint:         fed.TokenEndpoint,
			UserinfoEndpoint:      fed.UserinfoEndpoint,
			ClientID:              fed.ClientID,
			ClientSecret:          fed.ClientSecret,
			RedirectURI:           fed.RedirectURI,
			Scopes:                fed.Scopes,
			SubjectFieldOverride:  fed.SubjectFieldOverride,
			Timeout:               fed.Timeout,
		})
		if err != nil {
			logger.Error("oidc_federation skipped (bad config)", "name", fed.Name, "error", err)
			continue
		}
		auths = append(auths, auth)
		logger.Info("oidc_federation enabled", "provider", fed.Name, "authorization_endpoint", fed.AuthorizationEndpoint)
	}
	return auths, tempStore, totpAuth
}

func logEndpoints(cfg *config.Config, grpcListen string) {
	fmt.Println("HTTP endpoints:")
	for _, p := range []string{
		sso.PathHealth, sso.PathJWKS,
		sso.PathLogin, sso.PathSendCode, sso.PathCallback,
		sso.PathToken, sso.PathUserInfo, sso.PathLogout,
		sso.PathMyPermissions, sso.PathMyMenus, sso.PathMyRoles,
	} {
		fmt.Printf("  %s\n", p)
	}
	if cfg.Metrics.Enabled {
		fmt.Printf("  %s\n", "/metrics")
	}
	if cfg.Audit.Enabled && cfg.Audit.APIEnabled {
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathAuditEvents)
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathAuditEventByID)
	}
	if cfg.Network.Enabled && cfg.Network.APIEnabled {
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathNetPolicies)
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathNetPolicyByName)
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathNetPolicyClassify)
		fmt.Printf("  %s%s\n", sso.PathAPIPrefix, sso.PathNetPolicyResolveMe)
	}
	if cfg.Admin.Enabled && cfg.Admin.APIRESTEnabled {
		for _, p := range []string{
			"GET    /api/v1/admin/clients",
			"POST   /api/v1/admin/clients",
			"GET    /api/v1/admin/clients/{id}",
			"PATCH  /api/v1/admin/clients/{id}",
			"DELETE /api/v1/admin/clients/{id}",
			"POST   /api/v1/admin/clients/{id}:rotateSecret",
			"GET    /api/v1/admin/users",
			"POST   /api/v1/admin/users",
			"GET    /api/v1/admin/users/{id}",
			"PATCH  /api/v1/admin/users/{id}",
			"DELETE /api/v1/admin/users/{id}",
			"GET    /api/v1/admin/users/{user_id}/sessions",
			"GET    /api/v1/admin/sessions",
			"POST   /api/v1/admin/sessions:revoke",
			"POST   /api/v1/admin/tokens:issueTemp",
			"GET    /api/v1/admin/permissions/roles",
			"POST   /api/v1/admin/permissions/roles",
			"PATCH  /api/v1/admin/permissions/roles/{code}",
			"DELETE /api/v1/admin/permissions/roles/{code}",
			"GET    /api/v1/admin/permissions/assignments",
			"POST   /api/v1/admin/permissions:assign",
			"POST   /api/v1/admin/permissions:unassign",
			"PUT    /api/v1/admin/permissions/menus",
		} {
			fmt.Printf("  %s\n", p)
		}
		if cfg.Snapshot.Enabled {
			for _, p := range []string{
				"POST   /api/v1/admin/snapshots",
				"GET    /api/v1/admin/snapshots",
				"GET    /api/v1/admin/snapshots/{id}",
				"POST   /api/v1/admin/snapshots/{id}:restore",
				"DELETE /api/v1/admin/snapshots/{id}",
			} {
				fmt.Printf("  %s\n", p)
			}
		}
		if cfg.Releases.Enabled {
			for _, p := range []string{
				"POST   /api/v1/admin/releases",
				"GET    /api/v1/admin/releases",
				"GET    /api/v1/admin/releases:current",
				"GET    /api/v1/admin/releases/{id}",
				"POST   /api/v1/admin/releases/{id}:pin",
				"POST   /api/v1/admin/releases/{id}:rollback",
				"DELETE /api/v1/admin/releases/{id}",
			} {
				fmt.Printf("  %s\n", p)
			}
		}
	}
	if grpcListen != "" {
		fmt.Printf("gRPC services on %s:\n", grpcListen)
		fmt.Println("  snaplink.audit.v1.AuditWriter / Record + StreamEvents")
		fmt.Println("  snaplink.authz.v1.Authorizer / Check + List* + GetMenus")
		fmt.Println("  snaplink.discovery.v1.Discovery / Register + Discover + Watch")
		if cfg.Network.Enabled {
			fmt.Println("  snaplink.netpolicy.v1.PolicyService / Get + List + Apply + Delete + Watch + Classify")
		}
		if cfg.Admin.Enabled {
			fmt.Println("  snaplink.admin.v1.ClientAdminService / List + Get + Create + Update + Delete + RotateSecret")
			fmt.Println("  snaplink.admin.v1.UserAdminService / List + Get + Create + Update + Delete + ListUserSessions")
			fmt.Println("  snaplink.admin.v1.TokenAdminService / ListSessions + Revoke + IssueTempToken")
			fmt.Println("  snaplink.admin.v1.PermissionAdminService / *")
			if cfg.Snapshot.Enabled {
				fmt.Println("  snaplink.admin.v1.SnapshotAdminService / Export + List + Get + Restore + Delete")
			}
			if cfg.Releases.Enabled {
				fmt.Println("  snaplink.admin.v1.ReleaseAdminService / Register + List + Get + GetCurrent + Pin + Rollback + Delete")
			}
		}
	}
}

// --- helpers ---

// slogLogger adapts log/slog to the sso.Logger interface so the SDK can hand
// off to whatever sink the operator wants (stdout, journald, file...).
type slogLogger struct{ inner *slog.Logger }

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

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
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
