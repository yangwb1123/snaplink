package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/shared/spi"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"

	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"

	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"

	discoveryv1 "github.com/snaplink/sso/gen/proto/discovery/v1"

	netpolicyv1 "github.com/snaplink/sso/gen/proto/netpolicy/v1"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// buildHTTPServer wires the runtime handler and wraps it in an *http.Server with
// the shared timeouts. Split out so run stays a thin lifecycle sequence.
func buildHTTPServer(cfg *config.Config, a *app, logger spi.Logger) (*http.Server, error) {
	httpHandler, err := buildHTTPHandler(cfg, a, logger)
	if err != nil {
		return nil, fmt.Errorf("http handler: %w", err)
	}
	return &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           httpHandler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}, nil
}

// startHTTPServer launches the main HTTP listener in a goroutine, choosing TLS
// when both cert + key are supplied. A clean close (http.ErrServerClosed) sends
// nil; any other error is forwarded on errCh.
func startHTTPServer(httpSrv *http.Server, cfg *config.Config, logger spi.Logger, tlsCert, tlsKey string, errCh chan<- error) {
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
}

// startPprofServer launches the optional pprof listener on a SEPARATE listener
// bound to a trusted interface (default 127.0.0.1:6060). Never mounted on the
// public router — pprof leaks memory contents and the CPU profile is a DoS
// vector. Failure is non-fatal (log-only): profiling is observability, not a
// serving path. An explicit mux (not DefaultServeMux) keeps the handlers off
// any other server the process might run. Returns nil when pprof is disabled.
func startPprofServer(cfg *config.Config, logger spi.Logger) *http.Server {
	if !cfg.Server.Pprof.Enabled {
		return nil
	}
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
	pprofSrv := &http.Server{Addr: pprofAddr, Handler: pmux, ReadHeaderTimeout: readHeaderTimeout}
	go func() {
		logger.Info("pprof listening", "addr", pprofAddr)
		if err := pprofSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("pprof server failed", "error", err)
		}
	}()
	return pprofSrv
}

// startGRPCServer registers + serves the gRPC services on grpcListen in a
// goroutine. Returns (nil, nil) when grpcListen is empty (disabled). A bind
// failure is fatal (returned); a clean stop sends nil on errCh.
func startGRPCServer(a *app, grpcListen string, logger spi.Logger, tlsCert, tlsKey string, errCh chan<- error) (*grpc.Server, error) {
	if grpcListen == "" {
		return nil, nil
	}
	grpcSrv, err := newGRPCServer(a, tlsCert, tlsKey)
	if err != nil {
		return nil, fmt.Errorf("grpc server: %w", err)
	}
	ln, err := net.Listen("tcp", grpcListen)
	if err != nil {
		return nil, fmt.Errorf("grpc listen: %w", err)
	}
	go func() {
		logger.Info("grpc listening", "addr", grpcListen)
		if err := grpcSrv.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errCh <- fmt.Errorf("grpc: %w", err)
			return
		}
		errCh <- nil
	}()
	return grpcSrv, nil
}

// newGRPCServer registers every available service on a fresh grpc.Server
// with production-safe defaults: keepalive, max message size, connection
// timeout, and optional TLS when tlsCert + tlsKey are both non-empty.
func newGRPCServer(a *app, tlsCert, tlsKey string) (*grpc.Server, error) {
	opts, err := grpcServerOptions(a, tlsCert, tlsKey)
	if err != nil {
		return nil, err
	}
	s := grpc.NewServer(opts...)
	authzv1.RegisterAuthorizerServer(s, grpcserver.NewAuthzService(a.provider))
	discoveryv1.RegisterDiscoveryServer(s, grpcserver.NewDiscoveryService(a.registry))
	if a.adminMW != nil {
		registerAdminGRPCServices(s, a)
	}
	return s, nil
}

// grpcServerOptions assembles the production-safe server options — keepalive,
// max message size, connection timeout, admin interceptors, and optional TLS
// when tlsCert + tlsKey are both non-empty.
func grpcServerOptions(a *app, tlsCert, tlsKey string) ([]grpc.ServerOption, error) {
	var opts []grpc.ServerOption

	opts = append(opts,
		grpc.MaxRecvMsgSize(16*1024*1024),     // 16 MB — big admin lists
		grpc.MaxSendMsgSize(16*1024*1024),     // 16 MB — big admin responses
		grpc.ConnectionTimeout(5*time.Second), // guard against slow clients
		grpc.MaxConcurrentStreams(100),        // per-connection fairness
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     15 * time.Minute, // close idle connections after 15m
			MaxConnectionAge:      30 * time.Minute, // force reconnect every 30m
			MaxConnectionAgeGrace: 5 * time.Second,  // grace for in-flight RPCs
			Time:                  60 * time.Second, // ping interval
			Timeout:               20 * time.Second, // ping timeout
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second, // minimum ping interval
			PermitWithoutStream: false,           // require active stream for pings
		}),
		// Increase initial window sizes for large admin list responses.
		grpc.InitialWindowSize(256*1024),     // 256 KB — stream window
		grpc.InitialConnWindowSize(512*1024), // 512 KB — connection window
	)

	if a.adminMW != nil {
		opts = append(opts,
			grpc.UnaryInterceptor(a.adminMW.UnaryServerInterceptor()),
			grpc.StreamInterceptor(a.adminMW.StreamServerInterceptor()),
		)
	}

	// Optional TLS for gRPC (same cert as HTTP, or a dedicated gRPC pair).
	if tlsCert != "" && tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			return nil, fmt.Errorf("grpc tls: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	return opts, nil
}

// registerAdminGRPCServices registers the admin-plane services — reached only
// when the admin middleware is wired, exactly as the registrations ran inline
// in newGRPCServer.
func registerAdminGRPCServices(s *grpc.Server, a *app) {
	auditv1.RegisterAuditWriterServer(s, grpcserver.NewAuditService(a.recorder))
	if a.netStore != nil {
		netpolicyv1.RegisterPolicyServiceServer(s, grpcserver.NewNetPolicyService(a.netStore, a.classifier, a.recorder))
	}
	adminv1.RegisterClientAdminServiceServer(s, grpcserver.NewClientAdminService(a.clientStore, a.recorder, a.server.InvalidateDiscoveryCache, a.server.InvalidateClientCache))
	adminv1.RegisterUserAdminServiceServer(s, grpcserver.NewUserAdminService(a.userProvider, a.sessionMgr, a.recorder))
	adminv1.RegisterTokenAdminServiceServer(s, grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
		Sessions:            a.sessionMgr,
		TempStore:           a.tempStore,
		Issuers:             a.tokenIssuers,
		RevokeAcrossIssuers: a.server.RevokeAcrossIssuers,
		Recorder:            a.recorder,
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

// buildHTTPHandler composes the SSO Server's runtime handler with the
// optional grpc-gateway admin reverse proxy. The gateway is mounted under
// /api/v1/admin/ and gated by AdminMiddleware (bearer + admin scope).
