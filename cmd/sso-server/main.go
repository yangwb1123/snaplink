// Command sso-server is the production binary that wires up the snaplink/sso
// SDK into a runnable HTTP service. It loads a YAML config (see
// deploy/openresty/README.md for an example), supports graceful shutdown on
// SIGINT/SIGTERM, applies sensible HTTP timeouts, and (optionally) terminates
// TLS itself or sits behind an OpenResty / Envoy / NGINX reverse proxy.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/bootstrap"
	"github.com/snaplink/sso/bootstrap/builtin"
	bootstrapfile "github.com/snaplink/sso/bootstrap/file"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/defaultimpl"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"
	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	discoveryv1 "github.com/snaplink/sso/gen/proto/discovery/v1"
	netpolicyv1 "github.com/snaplink/sso/gen/proto/netpolicy/v1"
	"github.com/snaplink/sso/grpcserver"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/registry"
	"github.com/snaplink/sso/registry/memory"
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
	cfgPath := flag.String("config", "config.yaml", "path to YAML config")
	listenOverride := flag.String("listen", "", "override server.listen from config (e.g. :9090)")
	grpcListen := flag.String("grpc-listen", ":8081", "gRPC listen address ('' to disable)")
	tlsCert := flag.String("tls-cert", "", "TLS cert file (omit for HTTP)")
	tlsKey := flag.String("tls-key", "", "TLS key file (omit for HTTP)")
	logLevel := flag.String("log-level", "", "override logging.level (debug|info|error)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fail("config: %v", err)
	}
	if *listenOverride != "" {
		cfg.Server.Listen = *listenOverride
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}

	logger := newSlogLogger(cfg.Logging.Level)

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
	clientStore   sso.ClientStore
	userProvider  sso.UserProvider
	sessionMgr    sso.SessionManager
	tempStore     authenticators.TempTokenStore // may be nil when temp_token disabled
	tokenIssuers  map[string]sso.TokenIssuer

	adminMW *sso.AdminMiddleware // nil when admin disabled

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
	}
	return s
}

// buildHTTPHandler composes the SSO Server's runtime handler with the
// optional grpc-gateway admin reverse proxy. The gateway is mounted under
// /api/v1/admin/ and gated by AdminMiddleware (bearer + admin scope).
func buildHTTPHandler(cfg *config.Config, a *app, logger sso.Logger) (http.Handler, error) {
	base := a.server.Handler()
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

	runner := bootstrap.NewRunner(bootstrapNamespace, tracker,
		bootstrap.WithRecorder(a.recorder),
		bootstrap.WithLogger(bootstrapLogger{logger}),
	)
	runner.Register(builtin.Steps(seed)...)
	logger.Info("bootstrap: applying pending steps", "namespace", bootstrapNamespace, "state_file", statePath)
	return runner.Run(context.Background())
}

// bootstrapLogger adapts sso.Logger to bootstrap.Logger (Info/Error pair).
type bootstrapLogger struct{ inner sso.Logger }

func (b bootstrapLogger) Info(msg string, kv ...any)  { b.inner.Info(msg, kv...) }
func (b bootstrapLogger) Error(msg string, kv ...any) { b.inner.Error(msg, kv...) }

// buildApp wires every SDK component the config asks for and returns them
// as a bundle so HTTP and gRPC entrypoints can share instances.
func buildApp(cfg *config.Config, logger sso.Logger) (*app, error) {
	clientStore := defaultimpl.NewMemoryClientStore()
	for _, c := range cfg.Clients {
		clientStore.AddSeed(&sso.Client{
			ID:                    c.ID,
			Secret:                c.Secret,
			Name:                  c.Name,
			RedirectURIs:          c.RedirectURIs,
			AllowedScopes:         c.AllowedScopes,
			AllowedAuthenticators: c.AllowedAuthenticators,
			TokenStrategy:         c.TokenStrategy,
			Active:                c.Active,
		})
	}

	userProvider := defaultimpl.NewMemoryUserProvider()
	sessionMgr := defaultimpl.NewMemorySessionManager(cfg.Server.SessionTTL)
	jwtIssuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(cfg.Server.Issuer),
		defaultimpl.WithEd25519TokenTTL(cfg.Server.TokenTTL),
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
		sso.WithTracingMiddleware(),
		sso.WithTokenIssuer(sso.TokenStrategyJWT, jwtIssuer),
		sso.WithTokenIssuer(sso.TokenStrategySession, sessionIssuer),
		sso.WithUserProvider(userProvider),
		sso.WithClientStore(clientStore),
		sso.WithSessionManager(sessionMgr),
	)

	var recorder *audit.Recorder
	if cfg.Audit.Enabled {
		recorder = audit.New(
			audit.NewMemorySink(cfg.Audit.MemoryCapacity),
			audit.WithErrorHandler(func(err error) { logger.Error("audit sink", "error", err) }),
		)
		opts = append(opts, sso.WithAuditRecorder(recorder))
		if cfg.Audit.APIEnabled {
			opts = append(opts, sso.WithAuditAPI())
		}
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

	netStore, err := cfg.BuildNetworkStore()
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
	}

	auths, tempStore := buildAuthenticators(cfg, logger)
	for _, ath := range auths {
		opts = append(opts, sso.WithAuthenticator(ath))
	}

	srv := sso.NewServer(opts...)

	var adminMW *sso.AdminMiddleware
	if cfg.Admin.Enabled {
		adminMW = sso.NewAdminMiddleware(srv, provider)
	}

	reg := memory.New()
	addr := cfg.Server.Listen
	if addr == "" || addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	// Self-registration into the in-process memory registry: no TTL
	// because lifetime is bound to the process, not a separate broker.
	if err := reg.Register(context.Background(), &registry.Service{
		ID:      cfg.Server.Issuer + "-1",
		Name:    "sso",
		Address: addr,
		Tags:    []string{"sso"},
	}); err != nil {
		return nil, fmt.Errorf("registry register: %w", err)
	}
	return &app{
		server:       srv,
		recorder:     recorder,
		provider:     provider,
		registry:     reg,
		netStore:     netStore,
		classifier:   classifier,
		clientStore:  clientStore,
		userProvider: userProvider,
		sessionMgr:   sessionMgr,
		tempStore:    tempStore,
		tokenIssuers: tokenIssuers,
		adminMW:      adminMW,
		netStop:      netStop,
	}, nil
}

// buildAuthenticators returns the configured authenticators and the temp
// token store, when one is wired. The store is returned separately so the
// admin TokenAdminService can issue tokens against the same backing store.
func buildAuthenticators(cfg *config.Config, logger sso.Logger) ([]sso.Authenticator, authenticators.TempTokenStore) {
	var auths []sso.Authenticator
	var tempStore authenticators.TempTokenStore
	codeStore := authenticators.NewMemoryCodeStore()

	if a := cfg.Authenticators.Password; a != nil && a.Enabled {
		auths = append(auths, authenticators.NewPasswordAuthenticator(
			authenticators.PasswordVerifierFunc(func(_ context.Context, user, pass string) (*sso.AuthResult, error) {
				// Replace with bcrypt/argon2 against your user store.
				if user == "alice" && pass == "secret" {
					return &sso.AuthResult{UserID: "user-alice", ExternalID: user}, nil
				}
				return nil, errors.New("bad credentials")
			}),
		))
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
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		store.Register("svc-001", pub, &sso.Subject{ID: "service-001"})
		auths = append(auths, authenticators.NewKeyPairAuthenticator(store, a.MaxClockSkew))
	}

	if a := cfg.Authenticators.APIKey; a != nil && a.Enabled {
		store := authenticators.NewMemoryAPIKeyStore()
		store.Register("ak_demo", "sk_demo_secret_value", &sso.Subject{ID: "service-demo"})
		auths = append(auths, authenticators.NewAPIKeyAuthenticator(store))
	}

	if a := cfg.Authenticators.Certificate; a != nil && a.Enabled {
		auths = append(auths, authenticators.NewCertificateAuthenticator(x509.NewCertPool()))
	}
	return auths, tempStore
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
