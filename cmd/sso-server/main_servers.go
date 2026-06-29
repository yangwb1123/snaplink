package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/shared/spi"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"

	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"

	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"

	discoveryv1 "github.com/snaplink/sso/gen/proto/discovery/v1"

	netpolicyv1 "github.com/snaplink/sso/gen/proto/netpolicy/v1"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"google.golang.org/grpc"
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
func startGRPCServer(a *app, grpcListen string, logger spi.Logger, errCh chan<- error) (*grpc.Server, error) {
	if grpcListen == "" {
		return nil, nil
	}
	grpcSrv := newGRPCServer(a)
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

// newGRPCServer registers every available service on a fresh grpc.Server.
// Phase A: AuditWriter, Authorizer, Discovery (always). Phase B:
// PolicyService when network is enabled. Phase C: 4 admin services when
// admin is enabled — gated by AdminMiddleware's UnaryServerInterceptor.
func newGRPCServer(a *app) *grpc.Server {
	var opts []grpc.ServerOption
	if a.adminMW != nil {
		opts = append(opts,
			grpc.UnaryInterceptor(a.adminMW.UnaryServerInterceptor()),
			grpc.StreamInterceptor(a.adminMW.StreamServerInterceptor()),
		)
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
	return s
}

// buildHTTPHandler composes the SSO Server's runtime handler with the
// optional grpc-gateway admin reverse proxy. The gateway is mounted under
// /api/v1/admin/ and gated by AdminMiddleware (bearer + admin scope).
