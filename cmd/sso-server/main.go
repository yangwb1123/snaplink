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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/defaultimpl"
	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"
	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	discoveryv1 "github.com/snaplink/sso/gen/proto/discovery/v1"
	"github.com/snaplink/sso/grpcserver"
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
// reuse the same Recorder / Provider / Registry instances.
type app struct {
	server   *sso.Server
	recorder *audit.Recorder
	provider permissions.Provider
	registry registry.Registry
}

func run(cfg *config.Config, logger sso.Logger, tlsCert, tlsKey, grpcListen string) error {
	a, err := buildApp(cfg, logger)
	if err != nil {
		return err
	}
	defer a.registry.Close()

	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           a.server.Handler(),
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
	logger.Info("server stopped cleanly")
	return nil
}

// newGRPCServer registers all three Phase A services on a fresh grpc.Server.
func newGRPCServer(a *app) *grpc.Server {
	s := grpc.NewServer()
	auditv1.RegisterAuditWriterServer(s, grpcserver.NewAuditService(a.recorder))
	authzv1.RegisterAuthorizerServer(s, grpcserver.NewAuthzService(a.provider))
	discoveryv1.RegisterDiscoveryServer(s, grpcserver.NewDiscoveryService(a.registry))
	return s
}

// buildApp wires every SDK component the config asks for and returns them
// as a bundle so HTTP and gRPC entrypoints can share instances.
func buildApp(cfg *config.Config, logger sso.Logger) (*app, error) {
	clientStore := defaultimpl.NewMemoryClientStore()
	for _, c := range cfg.Clients {
		clientStore.Add(&sso.Client{
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

	opts := append(cfg.ServerOptions(),
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithLogger(logger),
		sso.WithTracingMiddleware(),
		sso.WithTokenIssuer(sso.TokenStrategyJWT, defaultimpl.NewEd25519JWTIssuer(
			defaultimpl.WithEd25519Issuer(cfg.Server.Issuer),
			defaultimpl.WithEd25519TokenTTL(cfg.Server.TokenTTL),
		)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer(
			defaultimpl.WithSessionTokenTTL(cfg.Server.SessionTTL),
		)),
		sso.WithUserProvider(newInMemoryUserProvider()),
		sso.WithClientStore(clientStore),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(cfg.Server.SessionTTL)),
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

	for _, a := range buildAuthenticators(cfg, logger) {
		opts = append(opts, sso.WithAuthenticator(a))
	}

	srv := sso.NewServer(opts...)

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
	return &app{server: srv, recorder: recorder, provider: provider, registry: reg}, nil
}

func buildAuthenticators(cfg *config.Config, logger sso.Logger) []sso.Authenticator {
	var auths []sso.Authenticator
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
		auths = append(auths, authenticators.NewTempTokenAuthenticator(
			authenticators.NewMemoryTempTokenStore(), a.TTL,
		))
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
	return auths
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
	if grpcListen != "" {
		fmt.Printf("gRPC services on %s:\n", grpcListen)
		fmt.Println("  snaplink.audit.v1.AuditWriter / Record + StreamEvents")
		fmt.Println("  snaplink.authz.v1.Authorizer / Check + List* + GetMenus")
		fmt.Println("  snaplink.discovery.v1.Discovery / Register + Discover + Watch")
	}
}

// --- helpers ---

type inMemoryUserProvider struct {
	users map[string]*sso.User
}

func newInMemoryUserProvider() *inMemoryUserProvider {
	return &inMemoryUserProvider{users: make(map[string]*sso.User)}
}

func (p *inMemoryUserProvider) GetByID(_ context.Context, id string) (*sso.User, error) {
	u, ok := p.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (p *inMemoryUserProvider) GetByExternalID(_ context.Context, provider, externalID string) (*sso.User, error) {
	for _, u := range p.users {
		if u.Provider == provider && u.ExternalID == externalID {
			return u, nil
		}
	}
	return nil, errors.New("user not found")
}

func (p *inMemoryUserProvider) CreateOrUpdate(_ context.Context, user *sso.User) error {
	p.users[user.ID] = user
	return nil
}

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
