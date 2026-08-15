package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/gen/proto/audit/v1"
	"github.com/yangwb1123/snaplink/gen/proto/authz/v1"
	"github.com/yangwb1123/snaplink/gen/proto/discovery/v1"
	"github.com/yangwb1123/snaplink/gen/proto/netpolicy/v1"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"net"
	"net/http"
	"net/http/pprof"
	"sync/atomic"
	"time"
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
// failure is fatal (returned); a clean stop sends nil on errCh. The
// transport posture is resolved here (fail-closed default, see
// decideGRPCTransport) and surfaced on the "grpc listening" log line.
func startGRPCServer(a *app, grpcListen string, logger spi.Logger, tlsCert, tlsKey, grpcTLSCert, grpcTLSKey string, grpcInsecure bool, errCh chan<- error) (*grpc.Server, error) {
	if grpcListen == "" {
		return nil, nil
	}
	tr, err := decideGRPCTransport(grpcListen, tlsCert, tlsKey, grpcTLSCert, grpcTLSKey, grpcInsecure)
	if err != nil {
		return nil, fmt.Errorf("grpc server: %w", err)
	}
	grpcSrv, err := newGRPCServer(a, tr, logger)
	if err != nil {
		return nil, fmt.Errorf("grpc server: %w", err)
	}
	ln, err := net.Listen("tcp", grpcListen)
	if err != nil {
		return nil, fmt.Errorf("grpc listen: %w", err)
	}
	go func() {
		logGRPCListen(logger, grpcListen, tr)
		if err := grpcSrv.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errCh <- fmt.Errorf("grpc: %w", err)
			return
		}
		errCh <- nil
	}()
	return grpcSrv, nil
}

// logGRPCListen logs the gRPC listener line with its resolved transport
// mode. The plaintext opt-out is the one deliberately dangerous state and
// gets a Warn when the concrete logger supports it (slogLogger does; the
// spi.Logger interface itself has no Warn level), falling back to Info for
// other implementations.
func logGRPCListen(logger spi.Logger, addr string, tr grpcTransport) {
	if tr.mode == grpcTransportOptOutPlaintext {
		if w, ok := logger.(interface{ Warn(string, ...any) }); ok {
			w.Warn("grpc listening (plaintext operator opt-out)", "addr", addr)
			return
		}
		logger.Info("grpc listening (plaintext operator opt-out)", "addr", addr)
		return
	}
	logger.Info("grpc listening", "addr", addr, "transport", tr.label())
}

// grpcServicesHolder late-binds the constructed *grpc.Server into the metrics
// interceptors' allowlist closure. grpc builds interceptors as server options
// BEFORE the *grpc.Server exists, so the allowlist (GetServiceInfo keys) can
// only be read lazily at the first RPC — which runs only after Serve starts,
// i.e. after newGRPCServer stored the server here (happens-before via the
// Serve goroutine). atomic.Pointer makes the visibility self-evident.
type grpcServicesHolder struct {
	srv atomic.Pointer[grpc.Server]
}

// allowlist snapshots the registered-service names (grpc forbids registration
// after Serve, so one snapshot is final). Nil while the server is not yet
// stored — the interceptor treats a nil snapshot as "trust the method name".
func (h *grpcServicesHolder) allowlist() map[string]struct{} {
	s := h.srv.Load()
	if s == nil {
		return nil
	}
	set := make(map[string]struct{})
	for name := range s.GetServiceInfo() {
		set[name] = struct{}{}
	}
	return set
}

// newGRPCServer registers every available service on a fresh grpc.Server
// with production-safe defaults: keepalive, max message size, connection
// timeout, and the transport resolved by decideGRPCTransport (fail-closed
// TLS by default). Health + reflection are registered LAST so the first
// readiness evaluation already sees the complete service set; the returned
// observability stop func is stored on the app for the shutdown path.
func newGRPCServer(a *app, tr grpcTransport, logger spi.Logger) (*grpc.Server, error) {
	holder := &grpcServicesHolder{}
	opts, err := grpcServerOptions(a, tr, logger, holder.allowlist)
	if err != nil {
		return nil, err
	}
	s := grpc.NewServer(opts...)
	holder.srv.Store(s)
	authzv1.RegisterAuthorizerServer(s, grpcserver.NewAuthzService(a.provider))
	discoveryv1.RegisterDiscoveryServer(s, grpcserver.NewDiscoveryService(a.registry))
	if a.adminMW != nil {
		registerAdminGRPCServices(s, a)
	}
	a.grpcHealthStop = grpcserver.RegisterObservability(s, a.server.BuildHandlerDeps().ReadyChecks, logger)
	return s, nil
}

// grpcServerOptions assembles the production-safe server options — keepalive,
// max message size, connection timeout, admin interceptors, and the TLS
// wiring for the resolved transport (MinVersion TLS1.2 floor). TLS material
// is loaded once at startup; rotation requires a restart (pre-existing
// limitation, unchanged).
func grpcServerOptions(a *app, tr grpcTransport, logger spi.Logger, services func() map[string]struct{}) ([]grpc.ServerOption, error) {
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

	opts = append(opts, grpcInterceptorOptions(a, logger, services)...)

	// otelgrpc at v0.68.0 exposes tracing via a stats handler, not
	// interceptors (the interceptor API was removed upstream). A stats
	// handler is invoked by grpc-go AROUND the whole interceptor chain, so
	// the span covers the full RPC including Recovery's panic→Internal
	// conversion — the same "observability outermost" property the chain
	// order below guarantees for the metrics interceptor. With no exporter
	// configured, tracing.Init leaves the global no-op provider, making
	// this a few no-op calls per RPC ("always wired, cheap when off").
	opts = append(opts, grpc.StatsHandler(otelgrpc.NewServerHandler()))

	if tr.mode == grpcTransportTLS {
		cert, err := tls.LoadX509KeyPair(tr.cert, tr.key)
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

// grpcInterceptorOptions builds the unary + stream interceptor chain.
//
// Chain order (outermost → innermost):
//
//	metrics (obs) → Recovery → adminMW → handler
//
// with the otelgrpc stats handler wrapping the whole chain at the grpc-go
// level (see grpcServerOptions).
//
// Metrics sits OUTSIDE Recovery — deliberately amending the historical
// "Recovery outermost" invariant — so it observes the codes.Internal error
// Recovery synthesizes from a handler/adminMW panic: a panic is still
// counted as code_class=server, and a client still sees the oracle-safe
// bare "internal error". The metrics interceptor itself is panic-safe
// (defensive recover): a panic inside the observability layer is converted
// to Internal and logged instead of crashing the process. Recovery still
// protects everything beneath it — the admin middleware included — and
// grpc-go installs no panic recovery of its own, so ANY unrecovered panic
// on this server — in a handler in interfaces/grpcserver, in a.adminMW's
// authorization/audit logic, or in an operator-injected store either one
// delegates to — is contained. This applies whether or not the admin plane
// is configured (authz/discovery are always registered, with or without
// a.adminMW).
func grpcInterceptorOptions(a *app, logger spi.Logger, services func() map[string]struct{}) []grpc.ServerOption {
	unaryInts := []grpc.UnaryServerInterceptor{
		grpcserver.MetricsUnaryServerInterceptor(a.metrics, logger, services),
		grpcserver.RecoveryUnaryServerInterceptor(logger),
	}
	streamInts := []grpc.StreamServerInterceptor{
		grpcserver.MetricsStreamServerInterceptor(a.metrics, logger, services),
		grpcserver.RecoveryStreamServerInterceptor(logger),
	}
	if a.adminMW != nil {
		unaryInts = append(unaryInts, a.adminMW.UnaryServerInterceptor())
		streamInts = append(streamInts, a.adminMW.StreamServerInterceptor())
	}
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInts...),
		grpc.ChainStreamInterceptor(streamInts...),
	}
}

// registerAdminGRPCServices registers the admin-plane services — reached only
// when the admin middleware is wired, exactly as the registrations ran inline
// in newGRPCServer.
func registerAdminGRPCServices(s *grpc.Server, a *app) {
	auditv1.RegisterAuditWriterServer(s, grpcserver.NewAuditService(a.recorder))
	if a.netStore != nil {
		netpolicyv1.RegisterPolicyServiceServer(s, grpcserver.NewNetPolicyService(a.netStore, a.classifier, a.recorder))
	}
	adminv1.RegisterClientAdminServiceServer(s, newClientAdminService(a))
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
	if a.keyAdmin != nil {
		adminv1.RegisterKeyAdminServiceServer(s, a.keyAdmin)
	}
	if a.snapshotPipeline != nil {
		adminv1.RegisterSnapshotAdminServiceServer(s, grpcserver.NewSnapshotAdminService(
			a.snapshotPipeline, a.snapshotStorage, a.snapshotter, a.snapshotRestorer, a.recorder, a.operationStore))
	}
	if a.releaseStore != nil {
		adminv1.RegisterReleaseAdminServiceServer(s, grpcserver.NewReleaseAdminService(
			a.releaseRegistry, a.releaseStore, a.recorder, a.operationStore))
	}
	if a.operationStore != nil {
		adminv1.RegisterOperationAdminServiceServer(s, grpcserver.NewOperationAdminService(a.operationStore))
	}
	if a.tenantStore != nil {
		adminv1.RegisterTenantAdminServiceServer(s, grpcserver.NewTenantAdminService(
			a.tenantStore, a.recorder, a.server.InvalidateTenantSuspensionCache,
			a.server.InvalidateTenantResidencyCache,
			a.server.RevokeTenantCredentials))
	}
}

func newClientAdminService(a *app) *grpcserver.ClientAdminService {
	service := grpcserver.NewClientAdminService(a.clientStore, a.recorder,
		a.server.InvalidateDiscoveryCache, a.server.InvalidateClientCache)
	service.SetClientDeletedHook(a.server.ReleaseDeletedClientQuota)
	return service
}

// buildHTTPHandler composes the SSO Server's runtime handler with the
// optional grpc-gateway admin reverse proxy. The gateway is mounted under
// /api/v1/admin/ and gated by AdminMiddleware (bearer + admin scope).

// grpcTransportMode is the resolved transport posture of the gRPC listener.
type grpcTransportMode int

const (
	// grpcTransportTLS serves with TLS (MinVersion TLS1.2), material from
	// the gRPC-specific flags or the shared HTTP pair.
	grpcTransportTLS grpcTransportMode = iota
	// grpcTransportLoopbackPlaintext serves plaintext on a loopback-only
	// address — safe by construction, deliberate.
	grpcTransportLoopbackPlaintext
	// grpcTransportOptOutPlaintext serves plaintext on ANY address because
	// the operator passed -grpc-insecure — explicit opt-out, warn-logged.
	grpcTransportOptOutPlaintext
)

// grpcTransport carries the resolved posture plus the effective TLS material
// (after the -grpc-tls-* → -tls-* fallback), so the Creds wiring in
// grpcServerOptions and the startup log line share one resolution.
type grpcTransport struct {
	mode grpcTransportMode
	cert string
	key  string
}

// label is the transport mode token used on the "grpc listening" log line.
func (t grpcTransport) label() string {
	switch t.mode {
	case grpcTransportTLS:
		return "tls"
	case grpcTransportLoopbackPlaintext:
		return "plaintext (loopback)"
	default:
		return "plaintext (operator opt-out)"
	}
}

// decideGRPCTransport resolves the gRPC listener's transport posture —
// FAIL CLOSED by default. The gRPC-specific flags fall back to the shared
// HTTP pair, and the matrix is:
//
//	cert+key set      -> TLS whatever the address (insecure is an error:
//	                     the opt-out and the material contradict each other)
//	one of pair set   -> startup error (asymmetric material)
//	unset + insecure  -> plaintext anywhere (explicit operator opt-out)
//	unset + loopback  -> plaintext on loopback only (127.0.0.0/8, ::1,
//	                     localhost; an empty host like ":8081" is NOT
//	                     loopback)
//	unset + otherwise -> startup error naming the missing material and the
//	                     three resolutions
//
// grpcListen "" (listener disabled) is handled by the caller before this
// function runs — it never reaches the matrix.
func decideGRPCTransport(grpcListen, tlsCert, tlsKey, grpcTLSCert, grpcTLSKey string, grpcInsecure bool) (grpcTransport, error) {
	cert := grpcTLSCert
	if cert == "" {
		cert = tlsCert
	}
	key := grpcTLSKey
	if key == "" {
		key = tlsKey
	}

	switch {
	case cert != "" && key != "":
		if grpcInsecure {
			return grpcTransport{}, errors.New("-grpc-insecure conflicts with TLS material (-grpc-tls-cert/-grpc-tls-key or the shared -tls-cert/-tls-key pair are both set)")
		}
		return grpcTransport{mode: grpcTransportTLS, cert: cert, key: key}, nil
	case cert != "" || key != "":
		return grpcTransport{}, fmt.Errorf("gRPC TLS material is asymmetric: cert=%q key=%q (set -grpc-tls-cert/-grpc-tls-key together, or the shared -tls-cert/-tls-key pair)", cert, key)
	case grpcInsecure:
		return grpcTransport{mode: grpcTransportOptOutPlaintext}, nil
	case grpcListenIsLoopback(grpcListen):
		return grpcTransport{mode: grpcTransportLoopbackPlaintext}, nil
	default:
		return grpcTransport{}, fmt.Errorf(
			"gRPC listener %s would serve plaintext and is refused by default: provide TLS material (-grpc-tls-cert/-grpc-tls-key or the shared -tls-cert/-tls-key pair), bind a loopback address, or pass -grpc-insecure to opt out explicitly",
			grpcListen)
	}
}

// grpcListenIsLoopback reports whether the listen address's host is a
// loopback address. An empty host (":8081") is deliberately NOT loopback —
// it binds every interface. "localhost" counts; anything that parses as an
// IP must be in 127.0.0.0/8 or ::1 (net.IP.IsLoopback) to count.
func grpcListenIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// wirePageCursorKey seeds the grpcadmin page-cursor MAC key from an
// existing deployment-stable secret when one is configured — the audit
// webhook HMAC signing secret, derived via HKDF (security.DerivePageCursorKey)
// — so in-flight admin page tokens survive restarts and round-robin across
// replicas of one deployment. No stable secret configured = leave the
// security package's ephemeral random default in place (single-replica
// semantics: cursors invalidate on restart, always with the same safe
// invalid page_token message). No new config key: this derives from a
// secret that already exists when it exists.

func (b *appBuilder) wirePageCursorKey() {
	if b.cfg.Audit.Webhook.SigningSecret == "" {
		return
	}
	key, err := security.DerivePageCursorKey([]byte(b.cfg.Audit.Webhook.SigningSecret))
	if err != nil {
		b.logger.Error("page-cursor key derivation failed; using ephemeral key", "error", err)
		return
	}
	security.InstallPageCursorKey(key)
}
