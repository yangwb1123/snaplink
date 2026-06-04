// Command sso-server is the production binary that wires up the snaplink/sso
// SDK into a runnable HTTP service. It loads a YAML config (see
// deploy/openresty/README.md for an example), supports graceful shutdown on
// SIGINT/SIGTERM, applies sensible HTTP timeouts, and (optionally) terminates
// TLS itself or sits behind an OpenResty / Envoy / NGINX reverse proxy.
package main

import "github.com/snaplink/sso/oidc"

import "github.com/snaplink/sso/spi"

import "github.com/snaplink/sso/oauth"

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
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
	"github.com/snaplink/sso/caep"
	"github.com/snaplink/sso/cluster"
	clusteretcd "github.com/snaplink/sso/cluster/etcd"
	clustermemory "github.com/snaplink/sso/cluster/memory"
	"github.com/snaplink/sso/config"
	configetcd "github.com/snaplink/sso/config/etcd"
	"github.com/snaplink/sso/cors"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/defaultimpl/cryptosigner"
	sqlitestores "github.com/snaplink/sso/defaultimpl/sqlite"
	"github.com/snaplink/sso/federation"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"
	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	discoveryv1 "github.com/snaplink/sso/gen/proto/discovery/v1"
	netpolicyv1 "github.com/snaplink/sso/gen/proto/netpolicy/v1"
	"github.com/snaplink/sso/geo"
	geostatic "github.com/snaplink/sso/geo/static"
	"github.com/snaplink/sso/grpcserver"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/migrate"
	"github.com/snaplink/sso/netpolicy"
	netpolicyetcd "github.com/snaplink/sso/netpolicy/etcd"
	"github.com/snaplink/sso/permissions"
	permsqlite "github.com/snaplink/sso/permissions/sqlite"
	"github.com/snaplink/sso/ratelimit"
	"github.com/snaplink/sso/region"
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
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/signingkeys"
	signingkeysetcd "github.com/snaplink/sso/signingkeys/etcd"
	signingkeysmemory "github.com/snaplink/sso/signingkeys/memory"
	"github.com/snaplink/sso/snapshot"
	encryptionaes "github.com/snaplink/sso/snapshot/encryption/aesgcm"
	encryptionnone "github.com/snaplink/sso/snapshot/encryption/none"
	encryptionpass "github.com/snaplink/sso/snapshot/encryption/passphrase"
	storagefile "github.com/snaplink/sso/snapshot/storage/file"
	storageinline "github.com/snaplink/sso/snapshot/storage/inline"
	"github.com/snaplink/sso/tenant"
	tenantmemory "github.com/snaplink/sso/tenant/memory"
	tenantsqlite "github.com/snaplink/sso/tenant/sqlite"
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
		adminv1.RegisterClientAdminServiceServer(s, grpcserver.NewClientAdminService(a.clientStore, a.recorder, a.server.InvalidateDiscoveryCache))
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
func buildHTTPHandler(cfg *config.Config, a *app, logger spi.Logger) (http.Handler, error) {
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
			Metrics:           a.metrics,
			AuditRecorder:     a.recorder,
		}
		// Data-residency on the WebAuthn login mint path: wire the region
		// resolver + the server's context-free ResidencyDecision seam ONLY
		// when region is configured (mirrors how WithRegionMiddleware /
		// WithTenantResidencyCheck are conditionally wired in buildApp). Both
		// left nil otherwise ⇒ no residency check for WebAuthn (byte-identical
		// to a non-residency deployment). The /auth/login path is already
		// residency-gated in-pipeline; this closes the raw-handler WebAuthn gap.
		if a.regionResolver != nil {
			deps.RegionResolver = a.regionResolver
			deps.ResidencyDecision = a.server.ResidencyDecision
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
	// Push approval callback (reference impl). Operators with a
	// custom gateway leave callback.enabled=false and SetStatus
	// directly from their own handler.
	if cfg.MFA.Provider.Push.Callback.Enabled && a.pushApprovalStore != nil {
		callbackDeps, err := buildPushCallbackDeps(cfg.MFA.Provider.Push.Callback, a.pushApprovalStore, a.pushNotify, logger)
		if err != nil {
			return nil, fmt.Errorf("push callback: %w", err)
		}
		if err := mountPushCallbackRoute(a.server, callbackDeps); err != nil {
			return nil, fmt.Errorf("mount push callback: %w", err)
		}
		logger.Info("push approval callback mounted at /push/approval/:id/:decision",
			"bearer_token_required", callbackDeps.BearerToken != "",
			"ip_allowlist_size", len(callbackDeps.AllowedCIDRs),
			"channel_notify", callbackDeps.Notify != nil)
	} else if cfg.MFA.Provider.Push.Callback.Enabled {
		logger.Info("push callback.enabled=true but push backend not configured — callback mount skipped")
	}
	// GDPR subject export/erase routes. Destructive (erase) + PII-
	// leaking (export), so only mounted when admin auth is enabled —
	// IsProtectedPath gates /api/v1/compliance/ the same as /admin/.
	if a.adminMW != nil {
		var refreshIdx oauth.RefreshTokenSubjectIndex
		if idx, ok := a.refreshTokenStore.(oauth.RefreshTokenSubjectIndex); ok {
			refreshIdx = idx
		}
		if err := mountComplianceRoutes(a.server, &complianceDeps{
			Users:    a.userProvider,
			Sessions: a.sessionMgr,
			Refresh:  refreshIdx,
			Clients:  a.clientStore,
			Recorder: a.recorder,
		}); err != nil {
			return nil, fmt.Errorf("mount compliance: %w", err)
		}
		logger.Info("compliance routes mounted",
			"export", complianceUsersPrefix+"{id}"+complianceExportSuffix,
			"erase", complianceUsersPrefix+"{id}"+complianceEraseSuffix)

		// SCIM 2.0 User provisioning (RFC 7643/7644). Lists/replaces/
		// deletes the whole user directory, so — like compliance — only
		// mounted when admin auth is enabled; IsProtectedPath gates
		// /api/v1/scim/ the same as /api/v1/admin/. /Groups additionally
		// requires a permissions.Provider (a SCIM group maps onto a role),
		// opted into via scim.groups.enabled.
		var scimGroups *scimGroupDeps
		if cfg.SCIM.Groups.Enabled {
			if a.provider == nil {
				return nil, fmt.Errorf("scim.groups.enabled requires permissions.enabled (a SCIM group maps onto a permissions role)")
			}
			scimGroups = &scimGroupDeps{provider: a.provider, clientID: cfg.SCIM.Groups.GroupClientID}
		}
		if err := mountSCIMRoutes(a.server, a.userProvider, a.recorder, scimGroups); err != nil {
			return nil, fmt.Errorf("mount scim: %w", err)
		}
		logger.Info("scim routes mounted", "base", scimBasePath, "groups", scimGroups != nil)
	}
	// SAML 2.0 (cluster: external/forked SAML module). When saml.handler
	// names a registered SAMLHandlerFactory (the operator registered it from
	// their forked main via RegisterSAMLHandlers — the SAML/XML/DSig deps
	// live there, never in this module's go.mod), build the SAML surface and
	// mount it on the SSO router. cfg.SAML.Handler == "" ⇒ this whole block
	// is a no-op (byte-identical to a build without SAML): no lookup, no
	// routes, no authenticator. The signing key is borrowed by the factory
	// off the JWT issuer's CryptoSigner() accessor (a stdlib crypto.Signer
	// for XML-DSig), reusing the JWKS key so SP metadata matches. SAML
	// endpoints (e.g. /saml/metadata, the ACS callback) are SP/IdP-public,
	// so — like the WebAuthn ceremony — they mount OUTSIDE the admin gate;
	// the admin-middleware wrap below only intercepts admin-prefixed paths.
	if cfg.SAML.Handler != "" {
		factory, ok := lookupSAMLHandlerFactory(cfg.SAML.Handler)
		if !ok {
			return nil, fmt.Errorf("saml.handler %q is not registered (call RegisterSAMLHandlers from your forked main); registered: %v",
				cfg.SAML.Handler, RegisteredSAMLHandlers())
		}
		set, err := factory(context.Background(), SAMLServerDeps{
			IssuerForClient:       a.server.IssuerForClient,
			ClientStore:           a.clientStore,
			SessionManager:        a.sessionMgr,
			UserProvider:          a.userProvider,
			Issuer:                cfg.Server.Issuer,
			AuditRecorder:         a.recorder,
			Logger:                logger,
			RegisterAuthenticator: a.server.RegisterAuthenticator,
		})
		if err != nil {
			return nil, fmt.Errorf("saml handler %q: %w", cfg.SAML.Handler, err)
		}
		if set != nil {
			for _, h := range set.Handlers {
				if err := a.server.Handle(h.Method, h.Path, h.Handler); err != nil {
					return nil, fmt.Errorf("mount saml %s %s: %w", h.Method, h.Path, err)
				}
			}
			for _, auth := range set.Authenticators {
				a.server.RegisterAuthenticator(auth)
			}
			if set.ReadyCheck != nil {
				a.server.AddReadyCheck("saml-"+cfg.SAML.Handler, set.ReadyCheck)
			}
			logger.Info("saml routes mounted",
				"handler", cfg.SAML.Handler,
				"routes", len(set.Handlers),
				"authenticators", len(set.Authenticators),
				"ready_check", set.ReadyCheck != nil)
		}
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
	if err := adminv1.RegisterClientAdminServiceHandlerServer(ctx, gw, grpcserver.NewClientAdminService(a.clientStore, a.recorder, a.server.InvalidateDiscoveryCache)); err != nil {
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
	if err := adminv1.RegisterPermissionAdminServiceHandlerServer(ctx, gw, grpcserver.NewPermissionAdminService(
		a.provider, a.recorder,
		func(_ context.Context, id string) { a.server.InvalidateAuthzPolicyBundleCache(id) })); err != nil {
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
			a.tenantStore, a.recorder, a.server.InvalidateTenantSuspensionCache,
			a.server.InvalidateTenantResidencyCache,
			func(ctx context.Context, id string) { _, _ = a.server.RevokeTenantRefreshTokens(ctx, id) })); err != nil {
			return nil, fmt.Errorf("gateway tenants: %w", err)
		}
	}
	logger.Info("admin REST gateway mounted", "prefix", adminAPIPathPrefix)

	// Outer mux: admin paths go through middleware → gateway; everything
	// else falls through to the SSO runtime handler.
	gated := a.adminMW.HTTPMiddleware(gw)
	mux := http.NewServeMux()
	mux.Handle(adminAPIPathPrefix, gated)
	// The authz policy-bundle export is a custom HTTP handler on the SSO
	// router (it needs the Server's bundle cache + provider), not a
	// gRPC-gateway route — but its path lives under /api/v1/admin/, which
	// the line above sends to the gateway. Route this exact path back to
	// `base` (already admin-gated at line ~665); ServeMux's longest-match
	// makes the exact pattern win over the /api/v1/admin/ subtree.
	if a.provider != nil {
		mux.Handle(sso.PathAuthzPolicyBundle, base)
	}
	mux.Handle("/", base)
	return mux, nil
}

// runBootstrap constructs the file-backed Tracker, the AdminSeed bundle,
// and runs every built-in step that hasn't yet been applied. Errors are
// fatal — the operator must succeed at first-boot init before we accept
// any traffic.
func runBootstrap(cfg *config.Config, a *app, logger spi.Logger) error {
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
// buildPairwiseSubjectStore picks the pairwise reverse-lookup
// backend. memory keeps the single-replica story; sqlite shares
// (pairwise → local) so /userinfo + revoke + end_session on any
// replica can resolve any in-flight bearer token.
func buildPairwiseSubjectStore(cfg config.PairwiseSubjectsConfig) (security.PairwiseSubjectStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return security.NewMemoryPairwiseSubjectStore(), "memory (single-replica only)", nil
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
func buildAccountLockout(cfg config.AccountLockoutConfig) (security.AccountLockout, string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		l := security.NewMemoryAccountLockout()
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

// buildSubjectClientIndex picks the security.SubjectClientIndex backend that
// drives OIDC BCL multi-RP fan-out. memory keeps the single-replica
// story; sqlite shares the index so a logout reaching any replica
// fans out to every client a subject has touched cluster-wide.
func buildSubjectClientIndex(cfg config.BCLIndexConfig) (security.SubjectClientIndex, string, error) {
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
func buildJTIReplayStore(cfg config.JTIReplayConfig) (security.JTIReplayStore, string, error) {
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

// buildSPIFFEOption assembles the WithSPIFFEJWTSVID option from config,
// loading the SPIRE trust-bundle JWKS from disk into a StaticJWKS. It
// fails LOUD on any missing required field — there is no safe default for
// the trust domain, the audience the SVID must bind to, or the trust
// bundle itself, and silently degrading would leave an operator believing
// SVID acceptance is on when it isn't (or, worse, accepting tokens it
// shouldn't).
// buildFederationConfig translates the YAML federation block onto the SDK
// federation.Config. Each configured trust anchor's JWKSFile is loaded into
// TrustAnchor.Keys at boot — those keys are the ROOT OF TRUST the trust-chain
// resolver (slice 2) verifies the anchor's fetched Entity Configuration
// against, NEVER the keys the fetched statement self-asserts. A configured-but-
// unloadable anchor (missing file, malformed/empty JWKS) is a BOOT ERROR: the
// resolver must never silently run without its root keys (a chain rooted in an
// empty key set would fail closed, but failing loud at boot names the misconfig
// instead of every resolution mysteriously rejecting). With no anchors
// configured the resolver is inert (slice-1 behavior, byte-identical).
//
// Unset TTLs stay zero so the SDK applies its defaults (24h statement TTL, 5m
// cache); unset depth/skew likewise default in the SDK.
func buildFederationConfig(cfg config.FederationConfig) (*federation.Config, error) {
	anchors := make([]federation.TrustAnchor, 0, len(cfg.TrustAnchors))
	for i, ta := range cfg.TrustAnchors {
		if ta.EntityID == "" {
			return nil, fmt.Errorf("federation.trust_anchors[%d].entity_id required", i)
		}
		if ta.JWKSFile == "" {
			return nil, fmt.Errorf("federation.trust_anchors[%d].jwks_file required (the anchor's root-of-trust keys)", i)
		}
		doc, err := os.ReadFile(ta.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("read federation.trust_anchors[%d].jwks_file: %w", i, err)
		}
		source, err := security.ParseStaticJWKS(doc)
		if err != nil {
			return nil, fmt.Errorf("parse federation.trust_anchors[%d] anchor JWKS: %w", i, err)
		}
		keys, err := source.GetJWKS(context.Background())
		if err != nil {
			return nil, fmt.Errorf("federation.trust_anchors[%d] anchor JWKS: %w", i, err)
		}
		anchors = append(anchors, federation.TrustAnchor{EntityID: ta.EntityID, JWKSFile: ta.JWKSFile, Keys: keys})
	}

	// §7 trust-mark issuers (slice 4b): load each authorized issuer's JWKS into
	// Keys — the root of trust the marks it signs are verified against (NEVER a
	// mark's self-asserted keys; an authorized issuer's keys are operator-pinned
	// here). A configured-but-unloadable issuer is a BOOT ERROR (the gate must
	// not silently run without an authorized issuer's keys, which would reject
	// every otherwise-valid mark and surface as a mysterious admission failure).
	tmIssuers := make([]federation.TrustMarkIssuer, 0, len(cfg.TrustMarkIssuers))
	for i, ti := range cfg.TrustMarkIssuers {
		if ti.EntityID == "" {
			return nil, fmt.Errorf("federation.trust_mark_issuers[%d].entity_id required", i)
		}
		if ti.JWKSFile == "" {
			return nil, fmt.Errorf("federation.trust_mark_issuers[%d].jwks_file required (the issuer's trust-mark signing keys)", i)
		}
		doc, err := os.ReadFile(ti.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("read federation.trust_mark_issuers[%d].jwks_file: %w", i, err)
		}
		source, err := security.ParseStaticJWKS(doc)
		if err != nil {
			return nil, fmt.Errorf("parse federation.trust_mark_issuers[%d] issuer JWKS: %w", i, err)
		}
		keys, err := source.GetJWKS(context.Background())
		if err != nil {
			return nil, fmt.Errorf("federation.trust_mark_issuers[%d] issuer JWKS: %w", i, err)
		}
		tmIssuers = append(tmIssuers, federation.TrustMarkIssuer{
			EntityID:     ti.EntityID,
			JWKSFile:     ti.JWKSFile,
			Keys:         keys,
			AllowedTypes: append([]string(nil), ti.AllowedTypes...),
		})
	}
	// A required type needs SOME authorized-issuer source, else it locks out
	// EVERY auto-registering RP. Normally that source is operator-configured
	// trust_mark_issuers; the opt-in federation-resolved path provides an
	// ALTERNATE source (issuers discovered via their trust chain + authorized by
	// the anchor's trust_mark_issuers). So a required type with no configured
	// issuers is a misconfig ONLY when the federation-resolved path is ALSO off.
	if len(cfg.RequiredTrustMarkTypes) > 0 && len(tmIssuers) == 0 && !cfg.AllowFederationResolvedTrustMarkIssuers {
		return nil, errors.New("federation.required_trust_mark_types set but no federation.trust_mark_issuers configured and allow_federation_resolved_trust_mark_issuers is false (a required trust mark with no authorized issuer source would admit no RP)")
	}
	// The federation-resolved issuer path needs a configured trust anchor: it is
	// the root of trust the issuer's chain must reach AND whose trust_mark_issuers
	// authorizes the issuer. Without any anchor the path is inert (the SDK gate
	// nil-checks the resolver), so a flag set with no anchors is a misconfig —
	// fail loud rather than silently never admitting a resolved issuer.
	if cfg.AllowFederationResolvedTrustMarkIssuers && len(anchors) == 0 {
		return nil, errors.New("federation.allow_federation_resolved_trust_mark_issuers is true but no federation.trust_anchors configured (the anchor is the root of trust that authorizes a resolved issuer)")
	}

	// §8 SUPERIOR role: load each configured subordinate's JWKS into Keys — the
	// keys this server VOUCHES FOR in the Subordinate Statement it issues about
	// the subordinate at /fetch. A configured-but-unloadable subordinate is a
	// BOOT ERROR: a statement vouching for an empty key set is useless and would
	// fail every downstream chain validation, so fail loud at boot rather than
	// silently issue an unusable statement. With no subordinates the §8 route is
	// unmounted + the entity config advertises no fetch endpoint (byte-identical
	// to a leaf OP).
	subordinates := make([]federation.SubordinateEntity, 0, len(cfg.Subordinates))
	for i, sub := range cfg.Subordinates {
		if sub.EntityID == "" {
			return nil, fmt.Errorf("federation.subordinates[%d].entity_id required", i)
		}
		if sub.JWKSFile == "" {
			return nil, fmt.Errorf("federation.subordinates[%d].jwks_file required (the keys this server vouches for the subordinate)", i)
		}
		doc, err := os.ReadFile(sub.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("read federation.subordinates[%d].jwks_file: %w", i, err)
		}
		source, err := security.ParseStaticJWKS(doc)
		if err != nil {
			return nil, fmt.Errorf("parse federation.subordinates[%d] subordinate JWKS: %w", i, err)
		}
		keys, err := source.GetJWKS(context.Background())
		if err != nil {
			return nil, fmt.Errorf("federation.subordinates[%d] subordinate JWKS: %w", i, err)
		}
		subordinates = append(subordinates, federation.SubordinateEntity{
			EntityID:       sub.EntityID,
			JWKSFile:       sub.JWKSFile,
			Keys:           keys,
			MetadataPolicy: sub.MetadataPolicy,
			Constraints:    subordinateConstraints(sub.Constraints),
		})
	}

	return &federation.Config{
		AuthorityHints:     append([]string(nil), cfg.AuthorityHints...),
		TrustAnchors:       anchors,
		Subordinates:       subordinates,
		OrganizationName:   cfg.OrganizationName,
		Contacts:           append([]string(nil), cfg.Contacts...),
		EntityStatementTTL: cfg.EntityStatementTTL,
		CacheTTL:           cfg.CacheTTL,
		MaxTrustChainDepth: cfg.MaxTrustChainDepth,
		MaxClockSkew:       cfg.MaxClockSkew,
		// Slice-3 auto-registration abuse resistance (only consulted when
		// auto_register is enabled). Unset ⇒ the SDK applies its defaults (30s
		// negative-cache TTL, 16 concurrent resolutions, 1024-entry cap).
		ResolutionNegativeCacheTTL:     cfg.ResolutionNegativeCacheTTL,
		MaxConcurrentResolutions:       cfg.ResolutionMaxConcurrency,
		ResolutionNegativeCacheMaxSize: cfg.ResolutionNegativeCacheMaxSize,
		// Slice-4b §7 trust-mark requirement (only consulted when non-empty +
		// auto_register on). Empty RequiredTrustMarkTypes ⇒ the gate is OFF
		// (byte-identical to the slice-3 path).
		RequiredTrustMarkTypes: append([]string(nil), cfg.RequiredTrustMarkTypes...),
		TrustMarkIssuers:       tmIssuers,
		// Slice-4c opt-in federation-resolved issuer path (default false ⇒ the
		// slice-4b configured-issuer gate is byte-identical). Only consulted when
		// RequiredTrustMarkTypes is non-empty.
		AllowFederationResolvedTrustMarkIssuers: cfg.AllowFederationResolvedTrustMarkIssuers,
	}, nil
}

// subordinateConstraints translates the YAML §6.2 constraints config onto the
// SDK federation.EntityConstraints authored into a Subordinate Statement.
// Returns nil when the operator configured no constraints (so the statement
// carries no constraints claim). Preserves the pointer/empty-slice distinctions
// the SDK relies on (max_path_length 0 = "no intermediates"; a non-nil empty
// allowed_entity_types = "only federation_entity"); a naming_constraints object
// is emitted only when at least one of permitted/excluded is non-empty.
func subordinateConstraints(c *config.SubordinateConstraintsConfig) *federation.EntityConstraints {
	if c == nil {
		return nil
	}
	out := &federation.EntityConstraints{MaxPathLength: c.MaxPathLength}
	if len(c.NamingConstraintsPermitted) > 0 || len(c.NamingConstraintsExcluded) > 0 {
		out.NamingConstraints = &federation.NamingConstraints{
			Permitted: append([]string(nil), c.NamingConstraintsPermitted...),
			Excluded:  append([]string(nil), c.NamingConstraintsExcluded...),
		}
	}
	if c.AllowedEntityTypes != nil {
		types := append([]string(nil), (*c.AllowedEntityTypes)...)
		out.AllowedEntityTypes = &types
	}
	return out
}

func buildSPIFFEOption(cfg config.SPIFFEConfig) (sso.Option, error) {
	if cfg.TrustDomain == "" {
		return nil, errors.New("spiffe.trust_domain required when spiffe.enabled")
	}
	if cfg.Audience == "" {
		return nil, errors.New("spiffe.audience required when spiffe.enabled")
	}
	if cfg.JWKSFile == "" {
		return nil, errors.New("spiffe.jwks_file required when spiffe.enabled")
	}
	doc, err := os.ReadFile(cfg.JWKSFile)
	if err != nil {
		return nil, fmt.Errorf("read spiffe.jwks_file: %w", err)
	}
	source, err := security.ParseStaticJWKS(doc)
	if err != nil {
		return nil, fmt.Errorf("parse spiffe trust bundle: %w", err)
	}
	var vopts []security.SPIFFEValidatorOption
	if cfg.MaxClockSkew > 0 {
		vopts = append(vopts, security.WithSPIFFEMaxClockSkew(cfg.MaxClockSkew))
	}
	return sso.WithSPIFFEJWTSVID(cfg.TrustDomain, cfg.Audience, source, vopts...), nil
}

// caepSubjectMode maps the YAML subject_mode string onto the SDK enum. It
// fails LOUD on an unrecognised value rather than silently defaulting —
// the wrong mode is a wrong-subject-revocation risk, so an operator typo
// must surface, not degrade.
func caepSubjectMode(raw string) (caep.SubjectMapMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "opaque":
		return caep.SubjectMapOpaque, nil
	case "iss_sub", "iss-sub":
		return caep.SubjectMapIssSub, nil
	default:
		return 0, fmt.Errorf("unknown caep.receiver subject_mode %q (want opaque|iss_sub)", raw)
	}
}

// buildCAEPReceiverOption assembles the WithCAEPReceiver option — the
// INBOUND half of OpenID Shared Signals. It loads each trusted
// transmitter's trust-bundle JWKS from disk, composes the revocation seam
// (sessions + refresh tokens) from the already-built stores, and wires a
// dedicated JTI-replay store for the SET jti namespace.
//
// It fails LOUD on any missing required field (audience, no transmitters, a
// transmitter without issuer/jwks_file, a bad subject_mode) — a half-wired
// receiver would either accept nothing or, worse, mis-map a subject, so a
// misconfiguration must stop boot, not degrade.
//
// The receiver's revocation reuses the SAME seams /token/revoke-all drives:
// the RefreshTokenSubjectIndex (when the refresh store supports it) + the
// SessionManager. A receiver that could revoke NOTHING (no session manager
// AND no subject-index refresh store) is rejected.
func buildCAEPReceiverOption(cfg config.CAEPReceiverConfig, sessionMgr sso.SessionManager, refreshStore oauth.RefreshTokenStore, clientStore sso.ClientStore, userProvider sso.UserProvider, recorder *audit.Recorder, metricsReg *metrics.Metrics, logger spi.Logger) (sso.Option, error) {
	if cfg.Audience == "" {
		return nil, errors.New("caep.receiver.audience required when caep.receiver.enabled")
	}
	if len(cfg.Transmitters) == 0 {
		return nil, errors.New("caep.receiver.transmitters requires at least one entry when caep.receiver.enabled")
	}

	transmitters := make([]caep.TrustedTransmitter, 0, len(cfg.Transmitters))
	for i, tt := range cfg.Transmitters {
		if tt.Issuer == "" {
			return nil, fmt.Errorf("caep.receiver.transmitters[%d].issuer required", i)
		}
		if tt.JWKSFile == "" {
			return nil, fmt.Errorf("caep.receiver.transmitters[%d].jwks_file required", i)
		}
		doc, err := os.ReadFile(tt.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("read caep.receiver.transmitters[%d].jwks_file: %w", i, err)
		}
		source, err := security.ParseStaticJWKS(doc)
		if err != nil {
			return nil, fmt.Errorf("parse caep.receiver.transmitters[%d] trust bundle: %w", i, err)
		}
		mode, err := caepSubjectMode(tt.SubjectMode)
		if err != nil {
			return nil, err
		}
		// iss_sub mode REQUIRES an operator-pinned provider. An empty provider
		// is insecure: the local-subject lookup would otherwise fall back to
		// the SET's attacker-controlled sub_id.iss, letting a trusted
		// transmitter revoke users federated from ANY other provider
		// (cross-IdP subject hijack). NewReceiver enforces this too; we fail
		// here first to name the exact knob.
		if mode == caep.SubjectMapIssSub && strings.TrimSpace(tt.Provider) == "" {
			return nil, fmt.Errorf("caep.receiver.transmitters[%d].provider required when subject_mode is iss_sub (the provider MUST be operator-pinned to this transmitter's federated namespace; an empty provider is insecure)", i)
		}
		transmitters = append(transmitters, caep.TrustedTransmitter{
			Issuer:        tt.Issuer,
			JWKS:          source,
			SubjectMode:   mode,
			Provider:      tt.Provider,
			AllowedEvents: tt.AllowedEvents,
			AllowedAlgs:   tt.AllowedAlgs,
		})
	}

	// Revocation seam: the RefreshTokenSubjectIndex (bulk subject revoke,
	// when the refresh store supports it) + the SessionManager. Identical to
	// the seams /token/revoke-all + the compliance Eraser use.
	var subjectIndex oauth.RefreshTokenSubjectIndex
	if idx, ok := refreshStore.(oauth.RefreshTokenSubjectIndex); ok {
		subjectIndex = idx
	}
	revoker, err := caep.NewStoreRevoker(sessionMgr, subjectIndex, clientStore)
	if err != nil {
		return nil, err
	}

	// Dedicated replay store for the SET jti namespace (ssf:<iss>:<jti>),
	// independent of the DPoP/actor-token replay store. Memory keeps the
	// single-replica story; a multi-replica receiver deployment SHOULD swap
	// this for a cluster-shared store so a replayed SET routed to a
	// different replica is still rejected. The receiver itself fails CLOSED
	// on any MarkSeen error regardless of backend.
	jti := defaultimpl.NewMemoryJTIReplayStore()

	ropts := []caep.ReceiverOption{
		caep.WithReceiverAuditRecorder(recorder),
		caep.WithReceiverLogger(logger),
	}
	if cfg.MaxClockSkew > 0 {
		ropts = append(ropts, caep.WithReceiverMaxClockSkew(cfg.MaxClockSkew))
	}
	if metricsReg != nil {
		ropts = append(ropts, caep.WithReceiverMetric(func(outcome string) {
			metricsReg.SSFSetsReceivedTotal.WithLabelValues(outcome).Inc()
		}))
	}

	rcv, err := caep.NewReceiver(cfg.Audience, jti, revoker, userProvider, transmitters, ropts...)
	if err != nil {
		return nil, err
	}
	return sso.WithCAEPReceiver(rcv), nil
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

// appendStorageHealthSource collects v as a per-store entry for the
// /api/v1/admin/storage-health report (WithStorageHealth). It mirrors
// appendReadyCheck's gating: only stores exposing Ping(ctx) are added, so
// process-local memory backends silently no-op (no reachability signal to
// report) and the report contains exactly the SQLite-backed stores — the
// same set /readyz aggregates, but with per-store detail.
//
// When the store also exposes DB() *sql.DB (every SQLite store does) the
// source carries a SchemaVersions closure that runs migrate.Status on that
// store's handle, so the report shows each store's migrate-namespace ->
// applied-version map. A store without an accessible *sql.DB is Ping-only
// (no schema_versions). name is operator-facing and MUST NOT carry a DSN or
// secret — the report never surfaces the connection string, only this label
// plus a generic reachability error.
func appendStorageHealthSource(sources []sso.StorageHealthSource, name string, v any) []sso.StorageHealthSource {
	p, ok := v.(interface{ Ping(context.Context) error })
	if !ok {
		return sources
	}
	src := sso.StorageHealthSource{Name: name, Ping: p.Ping}
	if d, ok := v.(interface{ DB() *sql.DB }); ok {
		db := d.DB()
		if db != nil {
			src.SchemaVersions = func(ctx context.Context) (map[string]int, error) {
				st, err := migrate.Status(ctx, db)
				if err != nil {
					return nil, err
				}
				out := make(map[string]int, len(st))
				for _, ns := range st {
					out[ns.Namespace] = ns.Version
				}
				return out, nil
			}
		}
	}
	return append(sources, src)
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
		return &security.HeaderClientCertExtractor{HeaderName: cfg.Header.Name, Encoding: enc}, fmt.Sprintf("HeaderClientCertExtractor (header=%q encoding=%q — TRUST EDGE MUST STRIP HEADER)", cfg.Header.Name, cfg.Header.Encoding), nil
	default:
		return nil, "", fmt.Errorf("security.mtls.backend %q (want tls|header)", cfg.Backend)
	}
}

func parseHeaderCertEncoding(s string) (security.HeaderCertEncoding, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "url-pem", "urlpem", "url_pem":
		return security.HeaderCertEncodingURLPEM, nil
	case "pem":
		return security.HeaderCertEncodingPEM, nil
	case "base64-der", "base64der", "base64_der":
		return security.HeaderCertEncodingBase64DER, nil
	default:
		return 0, fmt.Errorf("security.mtls.header.encoding %q (want url-pem|pem|base64-der)", s)
	}
}

func buildDPoPNonceProvider(cfg config.DPoPNonceConfig, logger spi.Logger) (sso.DPoPNonceProvider, error) {
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
func buildAuthCodeStore(cfg config.OAuthConfig) (oauth.AuthCodeStore, error) {
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

func buildRefreshTokenStore(cfg config.OAuthConfig) (oauth.RefreshTokenStore, error) {
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

func buildDeviceCodeStore(cfg config.OAuthConfig) (oauth.DeviceCodeStore, error) {
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

func buildPARStore(cfg config.OAuthConfig) (oauth.PARStore, error) {
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
// salt falls back to security.DefaultPairwiseSalt — fine for tests, not
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
func buildRegistry(cfg *config.RegistryConfig, logger spi.Logger) (registry.Registry, string, error) {
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

// buildInvalidationBus materializes the cross-replica cluster.Bus.
//
// Unset backend → nil bus: single-node deployments invalidate caches
// locally and need no bus, so this is the safe default. memory is
// per-process (a no-op for multi-replica); etcd is cluster-shared. The
// etcd path is constructed here so the transitive dep stays out of the
// cluster SPI, mirroring buildRegistry. Returns the kind for logging;
// the bus is fail-open, so it intentionally gets no /readyz check.
func buildInvalidationBus(cfg *config.ClusterBusConfig, logger spi.Logger) (cluster.Bus, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "":
		return nil, "", nil
	case "memory":
		logger.Info("invalidation bus", "backend", "memory")
		return clustermemory.New(), "memory", nil
	case "etcd":
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, "", errors.New("cluster.bus.etcd_endpoints required when cluster.bus.backend=etcd")
		}
		bus, err := clusteretcd.New(clusteretcd.Config{
			Endpoints:   cfg.EtcdEndpoints,
			Prefix:      cfg.EtcdPrefix,
			DialTimeout: cfg.EtcdDialTimeout,
			EventTTL:    cfg.EtcdEventTTL,
			Username:    cfg.EtcdUsername,
			Password:    cfg.EtcdPassword,
		})
		if err != nil {
			return nil, "", fmt.Errorf("cluster/etcd: %w", err)
		}
		logger.Info("invalidation bus", "backend", "etcd",
			"endpoints", cfg.EtcdEndpoints, "prefix", cfg.EtcdPrefix)
		return bus, "etcd", nil
	default:
		return nil, "", fmt.Errorf("unknown cluster.bus.backend %q", cfg.Backend)
	}
}

// buildSigningKeyRegistry constructs the shared signing-key registry for
// leaderless multi-replica JWKS aggregation. Returns (nil, "", nil) when
// disabled. memory is per-process (single-node / test); etcd is cluster-
// shared — each replica announces its public keys under a lease and peers
// Watch + adopt, so a token signed on one replica verifies on every replica.
// The etcd path is constructed here so the transitive dep stays out of the
// signingkeys SPI, mirroring buildInvalidationBus. The registry is fail-open
// (a dropped announcement only narrows a verify-set back toward local keys),
// so it intentionally gets no /readyz check.
func buildSigningKeyRegistry(cfg *config.SigningKeyRegistryConfig, logger spi.Logger) (signingkeys.Registry, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "":
		return nil, "", nil
	case "memory":
		logger.Info("signing key registry", "backend", "memory")
		return signingkeysmemory.New(), "memory", nil
	case "etcd":
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, "", errors.New("keys.signing_key_registry.etcd_endpoints required when backend=etcd")
		}
		reg, err := signingkeysetcd.New(signingkeysetcd.Config{
			Endpoints:   cfg.EtcdEndpoints,
			Prefix:      cfg.EtcdPrefix,
			DialTimeout: cfg.EtcdDialTimeout,
			// LeaseTTL is the backend fallback when an announcement's
			// LeaseSeconds is 0; the Server derives LeaseSeconds from the same
			// keys.signing_key_registry.lease_ttl, so the two agree.
			LeaseTTL: cfg.LeaseTTL,
			Username: cfg.EtcdUsername,
			Password: cfg.EtcdPassword,
		})
		if err != nil {
			return nil, "", fmt.Errorf("signingkeys/etcd: %w", err)
		}
		logger.Info("signing key registry", "backend", "etcd",
			"endpoints", cfg.EtcdEndpoints, "prefix", cfg.EtcdPrefix)
		return reg, "etcd", nil
	default:
		return nil, "", fmt.Errorf("unknown keys.signing_key_registry.backend %q", cfg.Backend)
	}
}

// signingKeyRotationConfig translates the YAML rotation config into a
// defaultimpl.RotationConfig (without OnRotate, which the caller
// attaches), returning ok=false when rotation is disabled or
// misconfigured (interval <= 0). Pure so it is unit-testable.
func signingKeyRotationConfig(cfg config.KeyRotationConfig) (defaultimpl.RotationConfig, bool) {
	if !cfg.Enabled || cfg.Interval <= 0 {
		return defaultimpl.RotationConfig{}, false
	}
	return defaultimpl.RotationConfig{
		Interval:    cfg.Interval,
		GracePeriod: cfg.GracePeriod,
	}, true
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

// buildPermissionsProvider returns the wired permissions.Provider
// (memory or sqlite per config) seeded with cfg.Permissions.Apps +
// cfg.Permissions.UserRoles. Returns (nil, nil) when permissions
// disabled.
//
// SQLite backend: seed step uses AddRole which returns ErrRoleExists
// on conflict — operators re-running cmd against an already-seeded
// DSN see harmless duplicate-seed warnings rather than wedged
// startup. AssignRoles overwrites (matches the memory peer's SET
// semantics) so re-seeds idempotently re-apply the YAML state.
func buildPermissionsProvider(cfg *config.Config, logger spi.Logger) (permissions.Provider, error) {
	if !cfg.Permissions.Enabled {
		return nil, nil
	}
	var p permissions.Provider
	backend := strings.ToLower(strings.TrimSpace(cfg.Permissions.Backend))
	switch backend {
	case "", "memory":
		p = permissions.NewMemoryProvider()
		logger.Info("permissions provider: memory (single-replica only)")
	case "sqlite":
		if cfg.Permissions.SQLite.DSN == "" {
			return nil, errors.New("permissions.sqlite.dsn required when permissions.backend=sqlite")
		}
		sp, err := permsqlite.New(cfg.Permissions.SQLite.DSN)
		if err != nil {
			return nil, fmt.Errorf("permissions sqlite: %w", err)
		}
		p = sp
		logger.Info("permissions provider: sqlite (cluster-shared)", "dsn", cfg.Permissions.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown permissions.backend %q (supported: memory, sqlite)", cfg.Permissions.Backend)
	}

	ctx := context.Background()
	var seededRoles, seededAssignments int
	for _, app := range cfg.Permissions.Apps {
		for _, role := range app.Roles {
			if err := p.AddRole(ctx, app.ClientID, role); err != nil {
				if errors.Is(err, permissions.ErrRoleExists) {
					// Idempotent re-seed: UpdateRole carries the
					// current permissions list to the existing row.
					if uerr := p.UpdateRole(ctx, app.ClientID, role); uerr != nil {
						logger.Error("permissions seed: role update failed", "client", app.ClientID, "role", role.Code, "error", uerr)
						continue
					}
				} else {
					logger.Error("permissions seed: role add failed", "client", app.ClientID, "role", role.Code, "error", err)
					continue
				}
			}
			seededRoles++
		}
		if app.Menus != nil {
			if err := p.SetMenus(ctx, app.ClientID, app.Menus); err != nil {
				logger.Error("permissions seed: set menus failed", "client", app.ClientID, "error", err)
			}
		}
	}
	for _, a := range cfg.Permissions.UserRoles {
		if err := p.AssignRoles(ctx, a.UserID, a.ClientID, a.Roles); err != nil {
			logger.Error("permissions seed: assign roles failed", "user", a.UserID, "client", a.ClientID, "error", err)
			continue
		}
		seededAssignments++
	}
	logger.Info("permissions seed complete",
		"roles", seededRoles,
		"assignments", seededAssignments)
	return p, nil
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
func buildRiskScorer(cfg *config.RiskConfig, logger spi.Logger) (spi.RiskScorer, error) {
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
func buildMFA(cfg config.MFAConfig, totpAuth *authenticators.TOTPAuthenticator, webauthnHelper *webauthn.Helper, logger spi.Logger) (spi.MFAProvider, spi.MFAChallengeStore, time.Duration, string, *sqlitestores.PushApprovalStore, func(string), error) {
	if !cfg.Enabled {
		return nil, nil, 0, "", nil, nil, nil
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
		return nil, nil, 0, "", nil, nil, err
	}

	// Challenge store: memory for single-replica, sqlite for clusters.
	// Same backend-selection pattern security.AccountLockout / security.SubjectClientIndex
	// use; the schema gets migrated at construction so no separate
	// boot step is required.
	backend := strings.ToLower(strings.TrimSpace(cfg.Challenge.Backend))
	var (
		store     spi.MFAChallengeStore
		storeKind string
	)
	switch backend {
	case "", "memory":
		store = defaultimpl.NewMemoryMFAChallengeStore()
		storeKind = "memory (single-replica only)"
	case "sqlite":
		if cfg.Challenge.SQLite.DSN == "" {
			return nil, nil, 0, "", nil, nil, errors.New("mfa.challenge.sqlite.dsn required when backend=sqlite")
		}
		s, err := sqlitestores.NewMFAChallengeStore(cfg.Challenge.SQLite.DSN)
		if err != nil {
			return nil, nil, 0, "", nil, nil, err
		}
		store = s
		storeKind = "sqlite (cluster-shared)"
	default:
		return nil, nil, 0, "", nil, nil, fmt.Errorf("unknown mfa.challenge.backend %q (supported: memory, sqlite)", backend)
	}

	logger.Info("mfa orchestration enabled",
		"provider", kind,
		"methods", provider.SupportedMethods(),
		"store", storeKind,
		"ttl", cfg.Challenge.TTL)

	return provider, store, cfg.Challenge.TTL, storeKind, capture.store, capture.notify, nil
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
// surfacing push-factor handles through the recursive multi-build.
// cmd's buildMFA inspects store to register a /readyz check + launch
// the PruneExpired loop, and notify to wire the channel-notify wakeup
// into the reference approval callback. Both stay nil for
// memory-backed push, absent push, or (notify) channel_notify=false.
type pushStoreCapture struct {
	store  *sqlitestores.PushApprovalStore
	notify func(approvalID string)
}

func buildMFAProviderByKind(kind string, outerKinds []string, pushCfg config.MFAPushConfig, totpAuth *authenticators.TOTPAuthenticator, webauthnHelper *webauthn.Helper, logger spi.Logger, capture *pushStoreCapture) (spi.MFAProvider, error) {
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
			// Surface Notify only when channel-notify is opted in — the
			// reference callback then wakes a blocked Verify directly.
			// The concrete type is always *PushMFAProvider here (this
			// case constructs it); the assertion just narrows from the
			// spi.MFAProvider return.
			if pushCfg.ChannelNotify {
				if pp, ok := provider.(*defaultimpl.PushMFAProvider); ok {
					capture.notify = pp.Notify
				}
			}
		}
		return provider, nil
	case "multi":
		if len(outerKinds) < 2 {
			return nil, errors.New("mfa.provider.kind=multi requires at least two entries in mfa.provider.kinds")
		}
		seen := make(map[string]struct{}, len(outerKinds))
		innerProviders := make([]spi.MFAProvider, 0, len(outerKinds))
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
// buildPushWebhookTransport validates the webhook config + returns
// the constructed transport. URL is required; everything else is
// optional + defaults apply. Operators wiring transport=webhook
// without a URL see a boot-time error rather than runtime delivery
// failures.
func buildPushWebhookTransport(cfg config.MFAPushWebhookConfig) (defaultimpl.PushTransport, error) {
	if cfg.URL == "" {
		return nil, errors.New("mfa.provider.push.webhook.url required when transport=webhook")
	}
	opts := []defaultimpl.PushWebhookOption{}
	if cfg.BearerToken != "" {
		opts = append(opts, defaultimpl.WithPushWebhookBearerToken(cfg.BearerToken))
	}
	for k, v := range cfg.Headers {
		opts = append(opts, defaultimpl.WithPushWebhookHeader(k, v))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, defaultimpl.WithPushWebhookClient(&http.Client{Timeout: cfg.Timeout}))
	}
	if cfg.RetryMaxAttempts > 0 || cfg.RetryInitialBackoff > 0 || cfg.RetryMaxBackoff > 0 {
		opts = append(opts, defaultimpl.WithPushWebhookRetry(
			cfg.RetryMaxAttempts,
			cfg.RetryInitialBackoff,
			cfg.RetryMaxBackoff,
		))
	}
	return defaultimpl.NewHTTPWebhookPushTransport(cfg.URL, opts...)
}

func buildPushMFAProvider(cfg config.MFAPushConfig, logger spi.Logger) (spi.MFAProvider, *sqlitestores.PushApprovalStore, error) {
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

	// Transport: log (default; writes to log) or webhook (POSTs to
	// operator-supplied URL via HTTPWebhookPushTransport). Custom
	// transports (FCM/APNs SDK) ship via SDK fork.
	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if transport == "" {
		transport = "log"
	}
	var pushTransport defaultimpl.PushTransport
	switch transport {
	case "log":
		pushTransport = defaultimpl.PushTransportFunc(func(_ context.Context, id, subject string, _ map[string]string) error {
			logger.Info("push approval delivered (log-only transport — set transport=webhook for real push)",
				"approval_id", id, "subject", subject)
			return nil
		})
	case "webhook":
		t, err := buildPushWebhookTransport(cfg.Webhook)
		if err != nil {
			return nil, nil, err
		}
		pushTransport = t
	default:
		return nil, nil, fmt.Errorf("unknown mfa.provider.push.transport %q (supported: log, webhook)", transport)
	}

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
func buildNetworkStore(cfg *config.NetworkConfig, logger spi.Logger) (netpolicy.Store, string, error) {
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
func buildSnapshotSubsystem(cfg *config.Config, logger spi.Logger) (*snapshot.Pipeline, snapshot.Storage, error) {
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
	case "aes-gcm", "aes-256-gcm":
		key, err := loadAESGCMKey(cfg.Snapshot.Encryption)
		if err != nil {
			return nil, nil, err
		}
		s, err := encryptionaes.New(key)
		if err != nil {
			return nil, nil, fmt.Errorf("snapshot aes-gcm: %w", err)
		}
		sealer = s
		logger.Info("snapshot encryption: aes-256-gcm (direct key from KMS)")
	default:
		return nil, nil, fmt.Errorf("unknown snapshot.encryption.backend %q (supported: none, passphrase, aes-gcm)", cfg.Snapshot.Encryption.Backend)
	}

	return &snapshot.Pipeline{Sealer: sealer}, store, nil
}

// loadAESGCMKey resolves the snapshot AES-GCM key from inline YAML
// (cfg.Key — discouraged, secrets in YAML hit git logs) or a file
// (cfg.KeyFile — recommended; KMS-fetched DEKs land there). The
// file or string can be raw 32 bytes, hex-encoded 64 chars, or
// base64-encoded ~44 chars; the helper tries each in turn so
// operators don't have to remember which encoder their KMS emits.
//
// Fails loud when neither source is set OR when no decoding scheme
// produces exactly 32 bytes — silent fallback would surface as
// cryptic AEAD errors at first Seal/Open.
func loadAESGCMKey(cfg config.SnapshotEncryptionConfig) ([]byte, error) {
	raw := []byte(cfg.Key)
	if len(raw) == 0 && cfg.KeyFile != "" {
		b, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("snapshot aes-gcm key file: %w", err)
		}
		// A 32-byte file is a raw binary key — use it verbatim. Only trim
		// a trailing newline for longer (text-encoded hex/base64) key
		// files. Trimming first would corrupt a raw key whose final byte
		// is 0x0A/0x0D (~0.78% of random 32-byte keys, e.g. a KMS DEK),
		// truncating it to 31 bytes and failing the load.
		if len(b) == 32 {
			return b, nil
		}
		raw = bytes.TrimRight(b, "\r\n")
	}
	if len(raw) == 0 {
		return nil, errors.New("snapshot.encryption.backend=aes-gcm requires key or key_file")
	}
	// Try raw bytes first (exactly 32).
	if len(raw) == 32 {
		return raw, nil
	}
	// Then hex (64 chars).
	if decoded, err := hex.DecodeString(string(raw)); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	// Then base64 (~44 chars).
	if decoded, err := base64.StdEncoding.DecodeString(string(raw)); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(string(raw)); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	return nil, fmt.Errorf("snapshot aes-gcm: key must decode to exactly 32 bytes (raw / hex / base64)")
}

// buildReleaseSubsystem materialises the releases.ReleaseStore +
// Pinner + Registry from ReleasesConfig. Returns (nil, nil, nil)
// when releases.enabled=false.
func buildReleaseSubsystem(cfg *config.Config, logger spi.Logger) (*releases.Registry, releases.ReleaseStore, error) {
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
func buildTenantStore(cfg *config.Config, logger spi.Logger) (tenant.Store, error) {
	if !cfg.Tenant.Enabled {
		return nil, nil
	}
	var store tenant.Store
	switch strings.ToLower(cfg.Tenant.Backend) {
	case "", "memory":
		store = tenantmemory.New()
		logger.Info("tenant store: memory (in-process)")
	case "sqlite":
		if cfg.Tenant.SQLite.DSN == "" {
			return nil, errors.New("tenant.sqlite.dsn required when tenant.backend=sqlite")
		}
		s, err := tenantsqlite.New(cfg.Tenant.SQLite.DSN)
		if err != nil {
			return nil, fmt.Errorf("tenant sqlite: %w", err)
		}
		store = s
		logger.Info("tenant store: sqlite (cluster-shared)", "dsn", cfg.Tenant.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown tenant.backend %q (supported: memory, sqlite)", cfg.Tenant.Backend)
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
func buildGeoProvider(cfg *config.Config, logger spi.Logger) (geo.Provider, error) {
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

// buildRegionResolver materialises the region.Resolver from RegionConfig.
// Returns nil when NEITHER ServingRegion NOR HeaderName is configured so cmd
// can skip WithRegionMiddleware entirely (the middleware is then NOT installed
// → byte-identical to a pre-region build). Mirrors buildGeoProvider's
// nil-when-disabled discipline.
//
// When configured it builds a ChainResolver that tries the trusted header
// FIRST (a regional edge/mesh pins traffic via HeaderName, anti-injection
// allowlisted by AllowedRegions), then falls back to the pinned ServingRegion.
// The HeaderResolver's Default is the pinned region too, so a single-region
// deployment that sets only ServingRegion still resolves every request to it.
func buildRegionResolver(cfg *config.Config) region.Resolver {
	servingRegion := region.ID(cfg.Region.ServingRegion)
	if servingRegion == "" && cfg.Region.HeaderName == "" {
		return nil
	}
	var allowed []region.ID
	if len(cfg.Region.AllowedRegions) > 0 {
		allowed = make([]region.ID, len(cfg.Region.AllowedRegions))
		for i, r := range cfg.Region.AllowedRegions {
			allowed[i] = region.ID(r)
		}
	}
	return region.ChainResolver{Resolvers: []region.Resolver{
		region.HeaderResolver{
			Header:  cfg.Region.HeaderName,
			Allowed: allowed,
			Default: servingRegion,
		},
		region.ConfigPinnedResolver{Region: servingRegion},
	}}
}

// bootstrapLogger adapts spi.Logger to bootstrap.Logger (Info/Error pair).
type bootstrapLogger struct{ inner spi.Logger }

func (b bootstrapLogger) Info(msg string, kv ...any)  { b.inner.Info(msg, kv...) }
func (b bootstrapLogger) Error(msg string, kv ...any) { b.inner.Error(msg, kv...) }

// buildApp wires every SDK component the config asks for and returns them
// as a bundle so HTTP and gRPC entrypoints can share instances.
// signingIssuer is the interface set cmd needs from the JWT signing
// issuer — satisfied by both *defaultimpl.Ed25519JWTIssuer and
// *defaultimpl.ECDSAJWTIssuer. The EdDSA-specific scheduled rotation
// loop is reached via a separate type assertion (ECDSA has no
// StartRotation today).
type signingIssuer interface {
	sso.TokenIssuer
	oidc.IDTokenIssuer
	sso.LogoutTokenIssuer
	// caep.JWTSigner (SignJWT) lets the same key mint Security Event
	// Tokens (RFC 8417) for the CAEP transmitter — one key, one JWKS
	// entry, every JWT shape.
	caep.JWTSigner
}

// buildSigningIssuer constructs the JWT signing issuer for the configured
// algorithm, optionally backed by an external KMS/HSM signer registered
// via RegisterExternalSigner. It returns the issuer, its canonical alg
// name (for logging + rotation gating), and any wiring error. An external
// signer is bridged into the issuer's seam via defaultimpl/cryptosigner;
// a mismatched key shape fails closed here at startup.
//
// The third return value is the instrumented external signer (nil for the
// in-process key path) — the caller hands it to appendReadyCheck so a
// wedged KMS/HSM trips /readyz.
func buildSigningIssuer(sc config.SigningConfig, srv config.ServerConfig, m *metrics.Metrics, logger spi.Logger) (signingIssuer, string, crypto.Signer, error) {
	// Resolve an optional external signer (KMS/HSM) up front; its kid
	// names the key in JWKS and token headers.
	var extSigner crypto.Signer
	var extKID string
	if name := strings.TrimSpace(sc.External); name != "" {
		f, ok := lookupExternalSigner(name)
		if !ok {
			return nil, "", nil, fmt.Errorf("keys.signing.external %q is not registered (registered: %v; call RegisterExternalSigner in your cmd binary)", name, registeredExternalSigners())
		}
		s, kid, err := f(context.Background())
		if err != nil {
			return nil, "", nil, fmt.Errorf("keys.signing.external %q: %w", name, err)
		}
		if s == nil {
			return nil, "", nil, fmt.Errorf("keys.signing.external %q returned a nil signer", name)
		}
		// Instrument the KMS/HSM round-trip (no-op when metrics disabled).
		extSigner = instrumentSigner(s, normalizeAlgLabel(sc.Alg), m, logger)
		extKID = kid
		logger.Info("signing key: external signer", "name", name, "kid", kid)
	}

	switch alg := strings.ToLower(strings.TrimSpace(sc.Alg)); alg {
	case "", "eddsa", "ed25519":
		opts := []defaultimpl.Ed25519Option{
			defaultimpl.WithEd25519Issuer(srv.Issuer),
			defaultimpl.WithEd25519TokenTTL(srv.TokenTTL),
			defaultimpl.WithEd25519MaxClockSkew(srv.MaxClockSkew),
		}
		if extSigner != nil {
			sgn, pub, err := cryptosigner.Ed25519(extSigner)
			if err != nil {
				return nil, "", nil, fmt.Errorf("keys.signing.external: %w", err)
			}
			opts = append(opts, defaultimpl.WithEd25519ExternalSigner(sgn, pub, extKID))
		}
		return defaultimpl.NewEd25519JWTIssuer(opts...), "EdDSA", extSigner, nil
	case "es256", "ecdsa":
		opts := []defaultimpl.ECDSAOption{
			defaultimpl.WithECDSAIssuer(srv.Issuer),
			defaultimpl.WithECDSATokenTTL(srv.TokenTTL),
			defaultimpl.WithECDSAMaxClockSkew(srv.MaxClockSkew),
		}
		if extSigner != nil {
			sgn, pub, err := cryptosigner.ECDSA(extSigner)
			if err != nil {
				return nil, "", nil, fmt.Errorf("keys.signing.external: %w", err)
			}
			opts = append(opts, defaultimpl.WithECDSAExternalSigner(sgn, pub, extKID))
		}
		return defaultimpl.NewECDSAJWTIssuer(opts...), "ES256", extSigner, nil
	case "rs256", "ps256", "rsa":
		signingAlg := "RS256"
		if alg == "ps256" {
			signingAlg = "PS256"
		}
		opts := []defaultimpl.RSAOption{
			defaultimpl.WithRSAIssuer(srv.Issuer),
			defaultimpl.WithRSAAlg(signingAlg),
			defaultimpl.WithRSATokenTTL(srv.TokenTTL),
			defaultimpl.WithRSAMaxClockSkew(srv.MaxClockSkew),
		}
		if extSigner != nil {
			sgn, pub, err := cryptosigner.RSA(extSigner, signingAlg)
			if err != nil {
				return nil, "", nil, fmt.Errorf("keys.signing.external: %w", err)
			}
			opts = append(opts, defaultimpl.WithRSAExternalSigner(sgn, pub, extKID))
		}
		return defaultimpl.NewRSAJWTIssuer(opts...), signingAlg, extSigner, nil
	default:
		return nil, "", nil, fmt.Errorf("keys.signing.alg %q unsupported (supported: eddsa, es256, rs256, ps256)", alg)
	}
}

func buildApp(cfg *config.Config, logger spi.Logger) (*app, error) {
	// Metrics constructed early so the retention schedulers can emit
	// counters when they fire. The asyncSink collector + WithMetrics
	// wiring still happen later (after the audit subsystem builds
	// asyncSink). Nil-safe — schedulers tolerate metricsRegistry=nil
	// when metrics are disabled.
	var metricsRegistry *metrics.Metrics
	if cfg.Metrics.Enabled {
		metricsRegistry = metrics.New()
	}

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
			Attributes:                       c.Attributes,
		}
		// Validate the CAEP receiver endpoint (https) at boot — a
		// non-https receiver would mean a SET (carrying a revocation
		// signal) is exfiltrated over plaintext. Same anti-exfil rule the
		// admin gRPC path enforces.
		if ep := c.Attributes[caep.AttrReceiverEndpoint]; ep != "" {
			if err := caep.ValidateReceiverEndpoint(ep); err != nil {
				return nil, fmt.Errorf("client %q caep_receiver_endpoint: %w", c.ID, err)
			}
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
	// Signing issuer: EdDSA (default) / ES256 / RS256|PS256, optionally
	// backed by an external KMS/HSM signer. Both concrete types satisfy
	// the same interface set; only the scheduled rotation loop below is
	// EdDSA-specific (type-asserted there).
	jwtIssuer, signingAlg, externalSigner, err := buildSigningIssuer(cfg.Keys.Signing, cfg.Server, metricsRegistry, logger)
	if err != nil {
		return nil, err
	}
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
		// Ed25519JWTIssuer satisfies oidc.IDTokenIssuer — sharing one
		// signing key keeps JWKS single-entry. Without this option the
		// id_token field is omitted from every /token + /auth/login
		// response and OIDC is silently disabled, which is the wrong
		// default for a binary called "sso-server".
		sso.WithIDTokenIssuer(jwtIssuer),
		// Pin the Server-level Validate alg gate to the wired signing
		// alg so an RP can never select the verification algorithm
		// (anti alg-confusion); discovery also reflects this set.
		sso.WithSupportedSigningAlgs(signingAlg),
	)
	logger.Info("signing issuer configured", "alg", signingAlg)
	// An external KMS/HSM signer is a runtime dependency the in-process
	// key path never had: register its passive health probe so a wedged
	// signer trips /readyz. nil (in-process key) silently no-ops.
	opts = appendReadyCheck(opts, "external-signer", externalSigner)
	opts = appendReadyCheck(opts, "sqlite-identity-clients", clientStore)
	opts = appendReadyCheck(opts, "sqlite-identity-users", userProvider)
	opts = appendReadyCheck(opts, "sqlite-identity-sessions", sessionMgr)

	// Per-store storage-health report sources (WithStorageHealth), gathered
	// at the same points as the /readyz checks above. Each SQLite store's
	// DB() handle drives migrate.Status for the schema-version view; memory
	// backends (no Ping) contribute nothing. Passed to WithStorageHealth
	// after all stores are wired.
	var storageHealthSources []sso.StorageHealthSource
	storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-identity-clients", clientStore)
	storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-identity-users", userProvider)
	storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-identity-sessions", sessionMgr)

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
			go runAuditRetention(retentionCtx, done, sqliteSink, interval, rc.MaxAge, logger, metricsRegistry)
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
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "audit-"+primaryName, primary)
	}

	provider, err := buildPermissionsProvider(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("permissions: %w", err)
	}
	if provider != nil {
		opts = append(opts, sso.WithPermissionProvider(provider))
		opts = appendReadyCheck(opts, "sqlite-permissions", provider)
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-permissions", provider)
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

	auths, tempStore, totpAuth, err := buildAuthenticators(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("authenticators: %w", err)
	}
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

	// Serving-region resolution + residency enforcement, wired alongside geo.
	// buildRegionResolver returns nil when region is unconfigured → the
	// middleware is NOT installed and the residency check stays inert
	// (byte-identical). When configured, the middleware-level AllowedRegions
	// backstop mirrors the header resolver's allowlist, and the residency
	// engine is enabled so the login gate enforces the tenant's policy.
	regionResolver := buildRegionResolver(cfg)
	if regionResolver != nil {
		var allowed []region.ID
		if len(cfg.Region.AllowedRegions) > 0 {
			allowed = make([]region.ID, len(cfg.Region.AllowedRegions))
			for i, r := range cfg.Region.AllowedRegions {
				allowed[i] = region.ID(r)
			}
		}
		opts = append(opts, sso.WithRegionMiddleware(regionResolver, region.MiddlewareOptions{
			AllowedRegions: allowed,
		}))
		opts = append(opts, sso.WithTenantResidencyCheck(cfg.Region.ResidencyCheckCacheTTL))
		logger.Info("region residency: enabled",
			"serving_region", cfg.Region.ServingRegion,
			"header_name", cfg.Region.HeaderName,
			"allowed_regions", cfg.Region.AllowedRegions,
		)
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
	storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-webauthn-users", webauthnUsers)
	storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-webauthn-sessions", webauthnSessions)

	// MFA orchestration wired AFTER the risk scorer so the wire-up
	// order matches the runtime gating order (Risk emits
	// DecisionRequireMFA → MFA orchestration consumes it). Without
	// both Provider + Store opts, RequireMFA decays to Allow — same
	// back-compat fall-through embedders see when they ship a Risk
	// scorer ahead of MFA.
	mfaProvider, mfaStore, mfaTTL, _, pushApprovalStore, pushNotify, err := buildMFA(cfg.MFA, totpAuth, webauthnHelper, logger)
	if err != nil {
		return nil, fmt.Errorf("mfa: %w", err)
	}
	if mfaProvider != nil && mfaStore != nil {
		opts = append(opts, sso.WithMFAProvider(mfaProvider))
		opts = append(opts, sso.WithMFAChallengeStore(mfaStore, mfaTTL))
		opts = appendReadyCheck(opts, "sqlite-mfa-challenges", mfaStore)
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-mfa-challenges", mfaStore)
	}
	// When push MFA wired with SQLite backend, surface the store
	// handle for /readyz wiring + the optional PruneExpired loop
	// (operators wanting bounded approval-table growth without
	// running external cron).
	var pushPruneCancel context.CancelFunc
	var pushPruneDone <-chan struct{}
	if pushApprovalStore != nil {
		opts = appendReadyCheck(opts, "sqlite-push-approvals", pushApprovalStore)
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-push-approvals", pushApprovalStore)
		if pi := cfg.MFA.Provider.Push.PruneInterval; pi > 0 {
			pruneCtx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			pushPruneCancel = cancel
			pushPruneDone = done
			go runPushApprovalPrune(pruneCtx, done, pushApprovalStore, pi, logger, metricsRegistry)
			logger.Info("push approvals: prune scheduler enabled", "interval", pi)
		}
	}

	// Anomaly detection: async behavioral detector pipeline. Off the
	// request hot path; runner.Dispatch is non-blocking; nil runtime
	// when anomaly.enabled=false (zero overhead).
	anomalyRT, err := buildAnomaly(cfg.Anomaly, recorder, metricsRegistry, logger)
	if err != nil {
		return nil, fmt.Errorf("anomaly: %w", err)
	}
	if anomalyRT != nil && anomalyRT.runner != nil {
		opts = append(opts, sso.WithAnomalyRunner(anomalyRT.runner))
		if anomalyRT.recentSQLite != nil {
			opts = appendReadyCheck(opts, "sqlite-anomaly-recent-logins", anomalyRT.recentSQLite)
			storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-anomaly-recent-logins", anomalyRT.recentSQLite)
		}
		if anomalyRT.ipFailSQLite != nil {
			opts = appendReadyCheck(opts, "sqlite-anomaly-ip-failures", anomalyRT.ipFailSQLite)
			storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-anomaly-ip-failures", anomalyRT.ipFailSQLite)
		}
		logger.Info("anomaly detection: enabled",
			"recent_login_backend", cfg.Anomaly.RecentLogin.Backend,
			"ip_failure_backend", cfg.Anomaly.IPFailure.Backend,
		)
	}

	tenantStore, err := buildTenantStore(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("tenant store: %w", err)
	}
	if tenantStore != nil {
		opts = append(opts, sso.WithTenantStore(tenantStore))
		// SQLite-backed tenant store implements Ping → /readyz.
		// Memory-backed silently no-ops (Ping isn't on the
		// interface; appendReadyCheck only registers when the
		// concrete type satisfies it).
		opts = appendReadyCheck(opts, "sqlite-tenant", tenantStore)
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-tenant", tenantStore)
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
	// DPoP proof iat-window tunables. Both default to 60s in the SDK when
	// the option is not wired, so a zero value here is byte-identical to
	// the previous hardcoded behavior — we only append when set.
	if cfg.DPoP.ProofMaxAge > 0 {
		opts = append(opts, sso.WithDPoPProofMaxAge(cfg.DPoP.ProofMaxAge))
	}
	if cfg.DPoP.MaxClockSkew > 0 {
		opts = append(opts, sso.WithDPoPMaxClockSkew(cfg.DPoP.MaxClockSkew))
	}
	if cfg.OAuth.AuthCode.Enabled {
		store, err := buildAuthCodeStore(cfg.OAuth)
		if err != nil {
			return nil, fmt.Errorf("oauth.auth_code: %w", err)
		}
		opts = append(opts, sso.WithAuthCodeStore(store, cfg.OAuth.AuthCode.TTL))
		opts = appendReadyCheck(opts, "sqlite-oauth-auth-codes", store)
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-oauth-auth-codes", store)
	}
	var refreshTokenStore oauth.RefreshTokenStore
	var refreshTokenTTL time.Duration
	if cfg.OAuth.RefreshToken.Enabled {
		store, err := buildRefreshTokenStore(cfg.OAuth)
		if err != nil {
			return nil, fmt.Errorf("oauth.refresh_token: %w", err)
		}
		opts = append(opts, sso.WithRefreshTokenStore(store, cfg.OAuth.RefreshToken.TTL))
		opts = appendReadyCheck(opts, "sqlite-oauth-refresh-tokens", store)
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-oauth-refresh-tokens", store)
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
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-oauth-device-codes", store)
	}
	if cfg.OAuth.PAR.Enabled {
		store, err := buildPARStore(cfg.OAuth)
		if err != nil {
			return nil, fmt.Errorf("par store: %w", err)
		}
		opts = append(opts, sso.WithPARStore(store, cfg.OAuth.PAR.TTL))
		opts = appendReadyCheck(opts, "sqlite-oauth-par", store)
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-oauth-par", store)
	}
	if jar := cfg.OAuth.JAR; jar.Enabled {
		f := security.NewHTTPJARFetcher()
		if jar.Timeout > 0 {
			f.Client.Timeout = jar.Timeout
		}
		if jar.MaxBytes > 0 {
			f.MaxBytes = jar.MaxBytes
		}
		opts = append(opts, sso.WithJARFetcher(f))
	}
	// CIBA poll mode. SQLite backend surfaces a handle for /readyz +
	// the optional PruneExpired loop (same contract as push approvals).
	var cibaPruneCancel context.CancelFunc
	var cibaPruneDone <-chan struct{}
	if cfg.CIBA.Enabled {
		store, transport, sqliteStore, err := buildCIBA(cfg.CIBA, logger)
		if err != nil {
			return nil, fmt.Errorf("ciba: %w", err)
		}
		opts = append(opts, sso.WithCIBA(store, transport, cfg.CIBA.RequestTTL, cfg.CIBA.Interval))
		if sqliteStore != nil {
			opts = appendReadyCheck(opts, "sqlite-ciba", sqliteStore)
			storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-ciba", sqliteStore)
			if pi := cfg.CIBA.PruneInterval; pi > 0 {
				pruneCtx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				cibaPruneCancel = cancel
				cibaPruneDone = done
				go runCIBAPrune(pruneCtx, done, sqliteStore, pi, logger, metricsRegistry)
				logger.Info("ciba: prune scheduler enabled", "interval", pi)
			}
		}
		mode := "poll"
		if cfg.CIBA.Ping.Enabled {
			opts = append(opts, sso.WithCIBAPingNotifier(newHTTPCIBAPingNotifier(cfg.CIBA.Ping, logger)))
			mode = "poll+ping"
		}
		logger.Info("ciba: enabled",
			"mode", mode,
			"backend", strings.ToLower(strings.TrimSpace(cfg.CIBA.Backend)),
			"transport", strings.ToLower(strings.TrimSpace(cfg.CIBA.Transport)))
	}
	if cfg.OAuth.JARM.Enabled {
		js, ok := any(jwtIssuer).(oidc.JARMSigner)
		if !ok {
			return nil, fmt.Errorf("oauth.jarm.enabled but the %s signing issuer does not implement JARM signing", signingAlg)
		}
		opts = append(opts, sso.WithJARM(js))
		logger.Info("jarm: enabled (response_mode=jwt)", "signing_alg", signingAlg)
	}
	if re := cfg.OIDC.ResponseEncryption; re.Enabled {
		backend := strings.ToLower(strings.TrimSpace(re.Backend))
		if backend == "" {
			backend = "rsa"
		}
		switch backend {
		case "rsa":
			opts = append(opts, sso.WithJWEResponseEncrypter(defaultimpl.NewRSAJWEResponseEncrypter()))
			logger.Info("oidc response encryption: enabled (RSA-OAEP-256 + A256GCM); per-client via id_token/userinfo_encrypted_response_alg")
		case "ecdh":
			opts = append(opts, sso.WithJWEResponseEncrypter(defaultimpl.NewECDHJWEResponseEncrypter()))
			logger.Info("oidc response encryption: enabled (ECDH-ES[+A256KW] + A256GCM); per-client via id_token/userinfo_encrypted_response_alg")
		case "multi":
			opts = append(opts, sso.WithJWEResponseEncrypter(defaultimpl.NewMultiJWEResponseEncrypter(
				defaultimpl.NewRSAJWEResponseEncrypter(),
				defaultimpl.NewECDHJWEResponseEncrypter(),
			)))
			logger.Info("oidc response encryption: enabled (RSA-OAEP-256 + ECDH-ES, A256GCM); routed per-client by registered key type")
		default:
			return nil, fmt.Errorf("oidc.response_encryption.backend %q unsupported (supported: rsa, ecdh, multi)", backend)
		}
	}
	if cr := cfg.ClientRegistration; cr.Enabled {
		opts = append(opts, sso.WithDynamicClientRegistration(oauth.DCRPolicy{
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
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-bcl-subject-client-index", idx)
		if n := cfg.BackchannelLogout.MaxConcurrent; n > 0 {
			opts = append(opts, sso.WithBackchannelLogoutMaxConcurrent(n))
		}
		logger.Info("backchannel logout: enabled", "subject_client_index", mode)
	}
	if cfg.CAEP.Enabled {
		// OpenID Shared Signals (CAEP/RISC) transmitter: real-time cross-RP
		// revocation. Reuses the same signing issuer (SET via its generic
		// SignJWT path) + the ClientStore (receivers resolved fresh per
		// event, no cache/bus) + the audit pipeline (tapped via
		// WithCAEPTransmitter). Best-effort, fail-open, opt-in — a delivery
		// failure never affects the revocation that already happened.
		caepOpts := []caep.Option{
			caep.WithIssuer(cfg.Server.Issuer),
			caep.WithLogger(logger),
			caep.WithFailureRecorder(recorder),
		}
		if metricsRegistry != nil {
			caepOpts = append(caepOpts, caep.WithMetric(func(outcome string) {
				metricsRegistry.CAEPSetsTotal.WithLabelValues(outcome).Inc()
			}))
		}
		if d := cfg.CAEP.ReceiverTimeout; d > 0 {
			caepOpts = append(caepOpts, caep.WithReceiverTimeout(d))
		}
		if d := cfg.CAEP.SETTTL; d > 0 {
			caepOpts = append(caepOpts, caep.WithSETTTL(d))
		}
		caepTx := caep.NewTransmitter(jwtIssuer, clientStore, caepOpts...)
		opts = append(opts, sso.WithCAEPTransmitter(caepTx))
		logger.Info("caep: OpenID Shared Signals transmitter enabled — signed SETs pushed to affected clients' registered receivers on revocation/suspension/family-reuse events")
	}
	if cfg.Federation.Enabled {
		// OpenID Federation 1.0 entity configuration: publish the OP's
		// self-signed Entity Statement so it is discoverable as a federation
		// ENTITY. The signer is the SAME signing issuer that mints tokens —
		// jwtIssuer satisfies federation.JWTSigner via its SignJWT seam — so
		// the entity statement verifies against a key already in JWKS (no new
		// trust setup). TrustAnchors are loaded into the config but inert in
		// this slice (trust-chain validation is a later slice).
		fedCfg, err := buildFederationConfig(cfg.Federation)
		if err != nil {
			return nil, fmt.Errorf("federation: %w", err)
		}
		opts = append(opts, sso.WithFederationEntity(fedCfg, jwtIssuer))
		logger.Info("federation: OpenID Federation 1.0 entity configuration enabled — self-signed Entity Statement served at /.well-known/openid-federation",
			"authority_hints", len(fedCfg.AuthorityHints),
			"trust_anchors", len(fedCfg.TrustAnchors),
			"subordinates", len(fedCfg.Subordinates),
		)
		if len(fedCfg.Subordinates) > 0 {
			// §8 SUPERIOR / INTERMEDIATE role: this server issues SIGNED
			// Subordinate Statements about its configured subordinates so a
			// resolver can climb THROUGH it. The /fetch route is mounted + the
			// entity config advertises federation_fetch_endpoint (gated on
			// subordinates; byte-identical leaf OP when none).
			logger.Info("federation: §8 Federation Fetch endpoint enabled — this server acts as a federation SUPERIOR/INTERMEDIATE, issuing signed Subordinate Statements about configured subordinates at /fetch (iss=this server, sub=looked-up subordinate, jwks=operator-configured vouched keys)",
				"subordinates", len(fedCfg.Subordinates),
			)
		}
		if len(fedCfg.TrustAnchors) > 0 {
			// Slice 2: the trust-chain resolver is now LIVE (anchors loaded). It
			// resolves + validates a remote entity's chain up to a configured
			// anchor. No endpoint is mounted in slice 2.
			logger.Info("federation: trust-chain resolution enabled — remote entities validated up to a configured trust anchor",
				"trust_anchors", len(fedCfg.TrustAnchors),
				"max_chain_depth", fedCfg.MaxTrustChainDepth,
			)
		}
		if cfg.Federation.AutoRegister {
			// Slice 3: automatic client registration. A validated federation RP
			// (chain rooted in a configured anchor) becomes a usable OAuth client
			// with no manual registration — derived on-the-fly from the policy-
			// constrained RP metadata when the authz endpoint misses its entity-id
			// client_id in the store. REQUIRES trust anchors (no root of trust ⇒
			// nothing to admit anyone), so fail loud rather than silently no-op.
			if len(fedCfg.TrustAnchors) == 0 {
				return nil, fmt.Errorf("federation: auto_register requires at least one trust_anchor (no root of trust to admit a federation client)")
			}
			opts = append(opts, sso.WithFederationAutoRegistration())
			logger.Info("federation: AUTOMATIC client registration enabled — a validated federation RP becomes a usable OAuth client with no manual registration (chain-vouched keys, no shared secret; policy-constrained metadata)",
				"trust_anchors", len(fedCfg.TrustAnchors),
			)
		}
	}
	if cfg.Server.OAuth21StrictMode {
		opts = append(opts, sso.WithOAuth21StrictMode(true))
		logger.Info("oauth2.1 strict mode: implicit grant disabled, S256-only PKCE, PKCE required for every login")
	}
	if prof := strings.ToLower(strings.TrimSpace(cfg.OAuth.Compliance.Profile)); prof != "" {
		switch prof {
		case "fapi_2", "fapi2", "fapi-2":
			mode := sso.FAPIModeEnforce
			if cfg.OAuth.Compliance.InspectionOnly {
				mode = sso.FAPIModeInspection
			}
			opts = append(opts, sso.WithFAPIProfile(mode))
			logger.Info("oauth compliance profile: fapi_2", "mode", mode.String(),
				"note", "PAR/JAR/DPoP-or-mTLS must be wired for clients to pass enforcement")
		default:
			return nil, fmt.Errorf("oauth.compliance.profile %q unsupported (supported: fapi_2)", prof)
		}
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
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-pairwise-subjects", store)
		logger.Info("oidc pairwise subjects: enabled", "store", mode)
	}
	if len(cfg.Server.SupportedACRValues) > 0 {
		opts = append(opts, sso.WithSupportedACRValues(cfg.Server.SupportedACRValues...))
	}
	if om := cfg.Server.OperatorMetadata; om.PolicyURI != "" || om.TosURI != "" || om.ServiceDocumentation != "" {
		opts = append(opts, sso.WithOperatorMetadata(om.PolicyURI, om.TosURI, om.ServiceDocumentation))
	}
	if cfg.Server.SignedMetadata {
		// jwtIssuer satisfies oidc.MetadataSigner — reuse the same
		// signing key as access + id + userinfo so JWKS continues to
		// cover everything with one entry.
		if signer, ok := any(jwtIssuer).(oidc.MetadataSigner); ok {
			opts = append(opts, sso.WithMetadataSigner(signer))
		} else {
			logger.Info("signed_metadata enabled but the configured JWT issuer does not implement oidc.MetadataSigner — discovery doc will not be signed")
		}
	}
	if cfg.Metrics.Enabled {
		// metricsRegistry was constructed at the top of buildApp so
		// retention schedulers could emit during their loops; here
		// we attach the AsyncSinkCollector (which needs the asyncSink
		// built by the audit subsystem) + wire the WithMetrics option.
		if asyncSink != nil {
			metricsRegistry.Registry.MustRegister(metrics.NewAsyncSinkCollector(asyncSink))
		}
		opts = append(opts, sso.WithMetrics(metricsRegistry))
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
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-jti-replay", store)
		if cfg.Security.JTIReplay.FailClosed {
			// Reject when the store can't confirm a jti is unseen,
			// instead of falling through. Closes the replay window
			// during a store outage at the cost of availability.
			opts = append(opts, sso.WithJTIReplayFailClosed())
		}
		logger.Info("security: jti replay protection enabled", "backend", mode, "fail_closed", cfg.Security.JTIReplay.FailClosed)
	}
	if cfg.SPIFFE.Enabled {
		spiffeOpt, err := buildSPIFFEOption(cfg.SPIFFE)
		if err != nil {
			return nil, fmt.Errorf("spiffe jwt-svid: %w", err)
		}
		opts = append(opts, spiffeOpt)
		logger.Info("spiffe: jwt-svid token-exchange acceptance enabled",
			"trust_domain", cfg.SPIFFE.TrustDomain,
			"audience", cfg.SPIFFE.Audience,
			"jwks_file", cfg.SPIFFE.JWKSFile,
		)
	}
	if cfg.CAEP.Receiver.Enabled {
		// OpenID Shared Signals (CAEP/SSF) RECEIVER — the inbound half. It
		// mounts /ssf/receive, consumes SETs from the configured trusted
		// transmitters, and revokes the mapped subject's local access via the
		// SAME seams /token/revoke-all uses. Fail-closed validation; unmapped
		// subject ⇒ ack + no-op (no wrongful revocation).
		rcvOpt, err := buildCAEPReceiverOption(cfg.CAEP.Receiver, sessionMgr, refreshTokenStore, clientStore, userProvider, recorder, metricsRegistry, logger)
		if err != nil {
			return nil, fmt.Errorf("caep receiver: %w", err)
		}
		opts = append(opts, rcvOpt)
		path := cfg.CAEP.Receiver.Path
		if path == "" {
			path = sso.PathSSFReceive
		}
		logger.Info("caep: OpenID Shared Signals receiver enabled — consumes signed SETs from trusted transmitters and revokes local access",
			"path", path,
			"audience", cfg.CAEP.Receiver.Audience,
			"trusted_transmitters", len(cfg.CAEP.Receiver.Transmitters))
	}
	if cfg.Mesh.ExtAuthz.Enabled {
		// Envoy/Istio ext_authz HTTP-mode endpoint (cluster C1 mesh
		// data-plane). Mesh-internal: only the trusted sidecar may call it,
		// and the mesh MUST strip any client-supplied X-Auth-* at ingress
		// (same edge-strip model as X-Forwarded-* / mtls.backend: header).
		path := cfg.Mesh.ExtAuthz.Path
		if path == "" {
			path = sso.PathMeshExtAuthz
		}
		opts = append(opts, sso.WithMeshExtAuthz(cfg.Mesh.ExtAuthz.Path))
		logger.Info("mesh: ext_authz HTTP endpoint enabled", "path", path)
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
		storageHealthSources = appendStorageHealthSource(storageHealthSources, "sqlite-account-lockout", lockout)
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

	// Cross-replica invalidation bus built before NewServer so the option
	// is in place; the subscriber is started just after (needs the Server).
	invalidationBus, _, err := buildInvalidationBus(&cfg.Cluster.Bus, logger)
	if err != nil {
		return nil, fmt.Errorf("invalidation bus: %w", err)
	}
	if invalidationBus != nil {
		opts = append(opts, sso.WithInvalidationBus(invalidationBus))
	}

	// Shared signing-key registry (opt-in leaderless multi-replica JWKS
	// aggregation). Built before NewServer so the option is in place; the
	// publish/subscribe loop starts just after (needs the Server). Default
	// the replica id to the same hostname-derived id the service registry
	// uses, so two replicas of one issuer announce distinct ids.
	signingKeyRegistry, _, err := buildSigningKeyRegistry(&cfg.Keys.SigningKeyRegistry, logger)
	if err != nil {
		return nil, fmt.Errorf("signing key registry: %w", err)
	}
	// srv is forward-declared so the signing-key-aggregation readiness check
	// (registered as an Option below) can close over it: the check runs at
	// /readyz probe time, long after srv = sso.NewServer(opts...) assigns it.
	var srv *sso.Server
	if signingKeyRegistry != nil {
		replicaID := strings.TrimSpace(cfg.Keys.SigningKeyRegistry.ReplicaID)
		if replicaID == "" {
			replicaID = resolveServiceID(cfg.Registry.ServiceID, cfg.Server.Issuer)
		}
		opts = append(opts,
			sso.WithSharedSigningKeyRegistry(signingKeyRegistry),
			sso.WithSigningKeyReplicaID(replicaID),
			sso.WithSigningKeyLeaseTTL(cfg.Keys.SigningKeyRegistry.LeaseTTL),
			// Trip /readyz when the aggregation subscriber goes degraded (its
			// registry stream closed and it's resubscribing) — the replica is
			// no longer adopting peers' keys, so it may reject valid peer
			// tokens. Registered ONLY when a registry is wired; nil registry ⇒
			// the loop never runs, the flag stays false, no check registered.
			sso.WithReadyCheck("signing-key-aggregation", func(context.Context) error {
				return srv.SigningKeyAggregationReady()
			}),
		)
		logger.Info("signing key aggregation enabled", "replica_id", replicaID)
	}

	// Mount the per-store storage-health admin report from the sources
	// gathered alongside the /readyz checks. Empty (all-memory backends) ⇒
	// WithStorageHealth doesn't mount the route — byte-identical to a build
	// without it. Admin-gated (admin:read) by the /api/v1/admin/ prefix.
	if len(storageHealthSources) > 0 {
		opts = append(opts, sso.WithStorageHealth(storageHealthSources...))
		logger.Info("storage-health report enabled", "stores", len(storageHealthSources))
	}

	srv = sso.NewServer(opts...)

	// Background ctx + Close-at-shutdown mirrors the netpolicy Classifier:
	// closing the bus ends the subscriber Watch, which closes busStop.
	busStop, err := srv.StartInvalidationBus(context.Background())
	if err != nil {
		if invalidationBus != nil {
			_ = invalidationBus.Close()
		}
		return nil, fmt.Errorf("invalidation bus subscribe: %w", err)
	}

	// Signing-key aggregation: publish our public keys + adopt peers'. Same
	// background-ctx + Close-at-shutdown shape as the invalidation bus —
	// closing the registry ends the subscriber stream, closing signingKeyStop.
	signingKeyStop, err := srv.StartSigningKeyAggregation(context.Background())
	if err != nil {
		if signingKeyRegistry != nil {
			_ = signingKeyRegistry.Close()
		}
		if invalidationBus != nil {
			_ = invalidationBus.Close()
		}
		return nil, fmt.Errorf("signing key aggregation start: %w", err)
	}

	// Automatic signing-key rotation. OnRotate emits an audit event and
	// busts the (signed) discovery doc cache cluster-wide — JWKS itself
	// is computed live, so /jwks.json reflects the new key immediately.
	var keyRotationStop <-chan struct{}
	var keyRotationCancel context.CancelFunc
	if rc, ok := signingKeyRotationConfig(cfg.Keys.Rotation); ok && strings.TrimSpace(cfg.Keys.Signing.External) != "" {
		// An external signer owns its key lifecycle in the KMS/HSM;
		// in-process RotateKey would mint a key the backend never sees.
		logger.Info("keys.rotation enabled but ignored: an external signer (keys.signing.external) manages its own key lifecycle; in-process scheduled rotation disabled")
	} else if ok {
		rec := recorder
		rc.OnRotate = func(oldKID, newKID string) {
			if rec != nil {
				rec.Record(context.Background(), &audit.Event{
					Type:      audit.EventSigningKeyRotated,
					Outcome:   audit.OutcomeSuccess,
					Timestamp: time.Now().UTC(),
					Reason:    "from=" + oldKID + " to=" + newKID,
				})
			}
			srv.InvalidateDiscoveryCache()
			if metricsRegistry != nil {
				metricsRegistry.SigningKeyRotationsTotal.Inc()
			}
			// Re-publish our keys so peers adopt the rotated kid (the
			// announcement replaces our prior one wholesale, dropping the
			// retired kid from peers' verify-sets after its grace window).
			// No-op when no signing-key registry is wired.
			if err := srv.PublishSigningKeys(context.Background()); err != nil {
				logger.Error("signingkeys: re-publish after rotation failed", "error", err)
			}
			logger.Info("signing key rotated", "from", oldKID, "to", newKID)
		}
		// All four built-in signing algs (EdDSA/ES256/RS256/PS256) ship a
		// StartRotation scheduler. The type assertion still guards the
		// loop so a custom WithTokenIssuer that implements only manual
		// RotateKey/RetireKey degrades gracefully (warn + skip) rather
		// than failing boot.
		if rotator, ok := jwtIssuer.(interface {
			StartRotation(context.Context, defaultimpl.RotationConfig) <-chan struct{}
		}); ok {
			rotCtx, cancel := context.WithCancel(context.Background())
			keyRotationCancel = cancel
			keyRotationStop = rotator.StartRotation(rotCtx, rc)
			logger.Info("signing key rotation enabled",
				"alg", signingAlg, "interval", rc.Interval, "grace_period", rc.GracePeriod)
		} else {
			logger.Info("keys.rotation enabled but the configured signing issuer has no scheduled-rotation support; skipping the rotation loop (manual rotation still available)",
				"alg", signingAlg)
		}
	}

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
		// Opt-in defense-in-depth: when set, EVERY export strips client
		// credentials so a plaintext export is safe to share/inspect.
		// NOT a restore path (see snapshot.Redactor) — encryption stays
		// the route for restorable backups. Default off = unchanged.
		if cfg.Snapshot.RedactSecrets {
			snapshotter.DefaultExportRedactor = snapshot.SnapshotRedactSecrets()
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
		go runSnapshotRetention(retentionCtx, done, snapStorage, interval, rc.Keep, logger, metricsRegistry)
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
		regionResolver:          regionResolver,
		webauthnHelper:          webauthnHelper,
		auditAsyncSink:          asyncSink,
		auditRetentionCancel:    auditRetentionCancel,
		auditRetentionDone:      auditRetentionDone,
		snapshotRetentionCancel: snapshotRetentionCancel,
		snapshotRetentionDone:   snapshotRetentionDone,
		pushPruneCancel:         pushPruneCancel,
		anomalyRT:               anomalyRT,
		pushPruneDone:           pushPruneDone,
		cibaPruneCancel:         cibaPruneCancel,
		cibaPruneDone:           cibaPruneDone,
		pushApprovalStore:       pushApprovalStoreIface(pushApprovalStore),
		pushNotify:              pushNotify,
		metrics:                 metricsRegistry,
		netStop:                 netStop,
		invalidationBus:         invalidationBus,
		busStop:                 busStop,
		signingKeyRegistry:      signingKeyRegistry,
		signingKeyStop:          signingKeyStop,
		keyRotationCancel:       keyRotationCancel,
		keyRotationStop:         keyRotationStop,
	}, nil
}

// pushApprovalStoreIface adapts the sqlite-typed handle into the
// defaultimpl interface — nil handle in → nil interface out so the
// callback wiring's nil-check works (a typed-nil-in-interface
// would slip past it).
func pushApprovalStoreIface(s *sqlitestores.PushApprovalStore) defaultimpl.PushApprovalStore {
	if s == nil {
		return nil
	}
	return s
}

// runPushApprovalPrune wakes every interval and calls
// PushApprovalStore.PruneExpired to bound the table size.
// Operators wanting bounded push-approval growth across an
// indefinite deployment lifetime wire this through
// mfa.provider.push.prune_interval rather than running external
// cron.
//
// Same shutdown contract as the audit / snapshot retention loops:
// close done on exit; Prune errors logged but don't tear down the
// loop. First prune fires after the first interval, not immediately.
func runPushApprovalPrune(ctx context.Context, done chan<- struct{}, store *sqlitestores.PushApprovalStore, interval time.Duration, logger spi.Logger, m *metrics.Metrics) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := store.PruneExpired(ctx)
			if err != nil {
				logger.Error("push approvals prune failed", "error", err)
				if m != nil {
					m.RetentionPruneErrorTotal.WithLabelValues("push_approvals").Inc()
				}
				continue
			}
			if deleted > 0 {
				logger.Info("push approvals pruned", "deleted", deleted)
				if m != nil {
					m.RetentionPrunedTotal.WithLabelValues("push_approvals").Add(float64(deleted))
				}
			}
		}
	}
}

// buildCIBA wires the CIBA poll-mode subsystem: the request store
// (memory | sqlite via the migrate framework) + the out-of-band
// challenge transport. The transport reuses the push primitives
// (log | webhook); since root sso cannot import defaultimpl, the
// PushTransport is adapted to oauth.CIBATransport via CIBATransportFunc.
// Returns the typed sqlite handle (or nil) for /readyz + prune wiring.
func buildCIBA(cfg config.CIBAConfig, logger spi.Logger) (oauth.CIBAStore, oauth.CIBATransport, *sqlitestores.CIBAStore, error) {
	var (
		store       oauth.CIBAStore
		sqliteStore *sqlitestores.CIBAStore
	)
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		store = defaultimpl.NewMemoryCIBAStore()
	case "sqlite":
		if cfg.SQLiteDSN == "" {
			return nil, nil, nil, errors.New("ciba.sqlite_dsn required when backend=sqlite")
		}
		s, err := sqlitestores.NewCIBAStore(cfg.SQLiteDSN)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("ciba.sqlite: %w", err)
		}
		store = s
		sqliteStore = s
	default:
		return nil, nil, nil, fmt.Errorf("unknown ciba.backend %q (supported: memory, sqlite)", cfg.Backend)
	}

	var pt defaultimpl.PushTransport
	switch strings.ToLower(strings.TrimSpace(cfg.Transport)) {
	case "", "log":
		pt = defaultimpl.PushTransportFunc(func(_ context.Context, id, subject string, _ map[string]string) error {
			logger.Info("ciba challenge delivered (log-only transport — set transport=webhook for real push)",
				"auth_req_id", id, "subject", subject)
			return nil
		})
	case "webhook":
		t, err := buildPushWebhookTransport(cfg.Webhook)
		if err != nil {
			return nil, nil, nil, err
		}
		pt = t
	default:
		return nil, nil, nil, fmt.Errorf("unknown ciba.transport %q (supported: log, webhook)", cfg.Transport)
	}
	return store, oauth.CIBATransportFunc(pt.Send), sqliteStore, nil
}

// runCIBAPrune wakes every interval and calls CIBAStore.PruneExpired
// to bound the request table. Same shutdown contract as the audit /
// snapshot / push retention loops: close done on exit, errors logged
// but never tear down the loop, first prune fires after the interval.
func runCIBAPrune(ctx context.Context, done chan<- struct{}, store *sqlitestores.CIBAStore, interval time.Duration, logger spi.Logger, m *metrics.Metrics) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := store.PruneExpired(ctx)
			if err != nil {
				logger.Error("ciba requests prune failed", "error", err)
				if m != nil {
					m.RetentionPruneErrorTotal.WithLabelValues("ciba").Inc()
				}
				continue
			}
			if deleted > 0 {
				logger.Info("ciba requests pruned", "deleted", deleted)
				if m != nil {
					m.RetentionPrunedTotal.WithLabelValues("ciba").Add(float64(deleted))
				}
			}
		}
	}
}

// runSnapshotRetention is the background loop cmd launches when
// snapshot.retention.enabled wires it. Same shutdown contract as
// runAuditRetention (close done channel on exit). First prune
// fires after the first interval, not immediately.
//
// PruneOldest errors don't tear down the loop — a transient
// storage outage shouldn't suspend retention forever; the loop
// logs + waits for the next tick.
func runSnapshotRetention(ctx context.Context, done chan<- struct{}, storage snapshot.Storage, interval time.Duration, keep int, logger spi.Logger, m *metrics.Metrics) {
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
				if m != nil {
					m.RetentionPruneErrorTotal.WithLabelValues("snapshot").Inc()
				}
				continue
			}
			if len(deleted) > 0 {
				logger.Info("snapshot retention pruned envelopes",
					"deleted_count", len(deleted), "keep", keep)
				if m != nil {
					m.RetentionPrunedTotal.WithLabelValues("snapshot").Add(float64(len(deleted)))
				}
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
func runAuditRetention(ctx context.Context, done chan<- struct{}, sink *auditsqlite.Sink, interval, maxAge time.Duration, logger spi.Logger, m *metrics.Metrics) {
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
				if m != nil {
					m.RetentionPruneErrorTotal.WithLabelValues("audit").Inc()
				}
				continue
			}
			if deleted > 0 {
				logger.Info("audit retention pruned events",
					"deleted", deleted, "cutoff", cutoff)
				if m != nil {
					m.RetentionPrunedTotal.WithLabelValues("audit").Add(float64(deleted))
				}
			}
		}
	}
}

// buildPrimaryAuditSink constructs the [audit.Sink] cmd places at
// the root of the sink composition (the one /audit query reads from
// + that gets wrapped by MultiSink+Webhook+Async). Backend selects
// between in-process MemorySink and the SQLite-backed Sink. Returns
// the sink + a short identifier used as the ReadyCheck suffix.
func buildPrimaryAuditSink(cfg config.AuditConfig, logger spi.Logger) (audit.Sink, string, error) {
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
func buildBcryptPasswordVerifier(users []config.PasswordUserConfig, logger spi.Logger) (authenticators.PasswordVerifier, int) {
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

// buildPasswordHealthChecker constructs the configured login-time
// credential-health checker. Kind selects the implementation: "" /
// "dictionary" is the fully-offline DictionaryPasswordHealthChecker
// (default, back-compatible); "hibp" is the online Have I Been Pwned
// k-anonymity breach checker (only a 5-char SHA-1 prefix ever leaves the
// process; fail-open so an outage never blocks login). An unknown Kind is
// a loud boot error rather than a silent fallback.
func buildPasswordHealthChecker(h *config.PasswordHealthConfig, logger spi.Logger) (spi.PasswordHealthChecker, error) {
	switch h.Kind {
	case "", "dictionary":
		checker, err := defaultimpl.NewDictionaryPasswordHealthChecker(defaultimpl.DictionaryPasswordHealthConfig{
			WeakPasswordFile: h.WeakPasswordFile,
		})
		if err != nil {
			return nil, err
		}
		logger.Info("password health checker enabled", "kind", "dictionary", "weak_password_file", h.WeakPasswordFile)
		return checker, nil
	case "hibp":
		opts := []defaultimpl.HIBPOption{
			// Surface fail-open HIBP outages in production; the check still
			// never blocks a login (the checker swallows the error itself).
			defaultimpl.WithHIBPLogger(logger),
		}
		var baseURL string
		if hc := h.HIBP; hc != nil {
			baseURL = hc.BaseURL
			if hc.BaseURL != "" {
				opts = append(opts, defaultimpl.WithHIBPBaseURL(hc.BaseURL))
			}
			if hc.Timeout > 0 {
				opts = append(opts, defaultimpl.WithHIBPTimeout(hc.Timeout))
			}
			if hc.MinCount > 0 {
				opts = append(opts, defaultimpl.WithHIBPMinCount(hc.MinCount))
			}
			if hc.UserAgent != "" {
				opts = append(opts, defaultimpl.WithHIBPUserAgent(hc.UserAgent))
			}
		}
		checker, err := defaultimpl.NewHIBPPasswordHealthChecker(opts...)
		if err != nil {
			return nil, err
		}
		// Log only the (non-secret) base URL — never a password or hash.
		logger.Info("password health checker enabled", "kind", "hibp", "base_url", baseURL)
		return checker, nil
	default:
		return nil, fmt.Errorf("unknown password health kind %q (want \"dictionary\" or \"hibp\")", h.Kind)
	}
}

// buildAuthenticators returns the configured authenticators, the temp
// token store (when wired), and the *TOTPAuthenticator handle (when
// TOTP is enabled). Both ancillary returns are separated so admin /
// MFA wiring downstream can reuse the same backing instances —
// admin TokenAdminService issues against the temp store; MFA
// orchestration wraps the TOTP authenticator with TOTPMFAProvider so
// step-up and primary auth share one secret store + skew policy.
// Both return nil when the corresponding authenticator is disabled.
//
// Returns an error when an authenticator's config is invalid (e.g. a
// missing weak-password extension file) — a misconfigured authenticator
// should fail the boot loudly, not silently degrade.
func buildAuthenticators(cfg *config.Config, logger spi.Logger) ([]sso.Authenticator, authenticators.TempTokenStore, *authenticators.TOTPAuthenticator, error) {
	var auths []sso.Authenticator
	var tempStore authenticators.TempTokenStore
	var totpAuth *authenticators.TOTPAuthenticator
	codeStore := authenticators.NewMemoryCodeStore()

	if a := cfg.Authenticators.Password; a != nil && a.Enabled {
		verifier, seeded := buildBcryptPasswordVerifier(a.Users, logger)
		var pwOpts []authenticators.PasswordOption
		if h := a.Health; h != nil && h.Enabled {
			checker, err := buildPasswordHealthChecker(h, logger)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("password health checker: %w", err)
			}
			// Pass the logger alongside the checker so a malfunctioning
			// custom checker (e.g. an HIBP lookup) is observable in
			// production; the health check stays fail-open regardless.
			pwOpts = append(pwOpts, authenticators.WithPasswordHealthChecker(checker), authenticators.WithPasswordLogger(logger))
		}
		auths = append(auths, authenticators.NewPasswordAuthenticator(verifier, pwOpts...))
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
	return auths, tempStore, totpAuth, nil
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

// slogLogger adapts log/slog to the spi.Logger interface so the SDK can hand
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
