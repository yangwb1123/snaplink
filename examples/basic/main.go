// Package main demonstrates an SSO server with all 7 authentication methods
// driven by a YAML config file.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"

	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/registry"
	"github.com/snaplink/sso/registry/memory"
)

const (
	demoUser      = "alice"
	demoPassword  = "secret"
	demoKeyID     = "svc-001"
	demoAPIKeyID  = "ak_demo"
	demoAPISecret = "sk_demo_secret_value"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

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

	opts := append(cfg.ServerOptions(),
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithTracingMiddleware(),
		// EdDSA JWT: real 3-segment header.payload.sig token that an upstream
		// gateway (lua-resty-jwt etc.) can verify locally via /.well-known/jwks.json.
		sso.WithTokenIssuer(sso.TokenStrategyJWT, defaultimpl.NewEd25519JWTIssuer(
			defaultimpl.WithEd25519Issuer(cfg.Server.Issuer),
			defaultimpl.WithEd25519TokenTTL(cfg.Server.TokenTTL),
		)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer(
			defaultimpl.WithSessionTokenTTL(cfg.Server.SessionTTL),
		)),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(clientStore),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(cfg.Server.SessionTTL)),
	)

	if cfg.Audit.Enabled {
		recorder := audit.New(
			audit.NewMemorySink(cfg.Audit.MemoryCapacity),
			audit.WithErrorHandler(func(err error) { log.Printf("audit: %v", err) }),
		)
		opts = append(opts, sso.WithAuditRecorder(recorder))
		if cfg.Audit.APIEnabled {
			opts = append(opts, sso.WithAuditAPI())
		}
	}

	if provider := cfg.BuildPermissionProvider(); provider != nil {
		opts = append(opts, sso.WithPermissionProvider(provider))
		if cfg.Permissions.EmbedInLogin {
			opts = append(opts, sso.WithEmbedPermissionsInLogin())
		}
	}

	for _, a := range buildAuthenticators(cfg) {
		opts = append(opts, sso.WithAuthenticator(a))
	}

	server := sso.NewServer(opts...)
	handler := server.Handler()

	fmt.Printf("SSO server on %s (issuer=%s)\n", cfg.Server.Listen, cfg.Server.Issuer)
	fmt.Println("Endpoints:")
	fmt.Printf("  POST %s\n", sso.PathLogin)
	fmt.Printf("  POST %s\n", sso.PathSendCode)
	fmt.Printf("  GET  %s\n", sso.PathCallback)
	fmt.Printf("  POST %s\n", sso.PathToken)
	fmt.Printf("  GET  %s\n", sso.PathUserInfo)
	fmt.Printf("  POST %s\n", sso.PathLogout)
	fmt.Printf("  GET  %s\n", sso.PathHealth)
	fmt.Printf("  GET  %s    (gateway verifies EdDSA JWTs locally)\n", sso.PathJWKS)
	if cfg.Audit.Enabled && cfg.Audit.APIEnabled {
		fmt.Printf("  GET  %s%s\n", sso.PathAPIPrefix, sso.PathAuditEvents)
		fmt.Printf("  GET  %s%s\n", sso.PathAPIPrefix, sso.PathAuditEventByID)
	}
	if cfg.Permissions.Enabled {
		fmt.Printf("  GET  %s?client_id=...\n", sso.PathMyPermissions)
		fmt.Printf("  GET  %s?client_id=...\n", sso.PathMyMenus)
		fmt.Printf("  GET  %s?client_id=...\n", sso.PathMyRoles)
	}

	// Service discovery: register self in an in-memory registry. Swap
	// memory.New() for etcd.New(...) when you have an etcd cluster.
	reg := memory.New()
	defer reg.Close()
	self := &registry.Service{
		ID:      "sso-1",
		Name:    "sso",
		Address: "127.0.0.1",
		Port:    8080,
		Tags:    []string{"v1"},
		TTL:     30 * time.Second,
	}
	if err := reg.Register(context.Background(), self); err != nil {
		log.Fatalf("registry: %v", err)
	}
	fmt.Printf("Registered as %s/%s @ %s\n", self.Name, self.ID, self.Endpoint())

	log.Fatal(http.ListenAndServe(cfg.Server.Listen, handler))
}

// buildAuthenticators returns the enabled set of authenticators based on the
// config. Code-only inputs (verifiers, senders, key material) are wired here.
func buildAuthenticators(cfg *config.Config) []sso.Authenticator {
	var auths []sso.Authenticator
	codeStore := authenticators.NewMemoryCodeStore()

	if a := cfg.Authenticators.Password; a != nil && a.Enabled {
		auths = append(auths, authenticators.NewPasswordAuthenticator(
			authenticators.PasswordVerifierFunc(func(_ context.Context, user, pass string) (*sso.AuthResult, error) {
				if user == demoUser && pass == demoPassword {
					return &sso.AuthResult{UserID: "user-" + user, ExternalID: user}, nil
				}
				return nil, errors.New("bad credentials")
			}),
		))
	}

	if a := cfg.Authenticators.Phone; a != nil && a.Enabled {
		auths = append(auths, authenticators.NewPhoneAuthenticator(
			codeStore,
			authenticators.SMSSenderFunc(func(_ context.Context, phone, code string) error {
				log.Printf("[sms stub] -> %s : %s", phone, code)
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
				log.Printf("[email stub] -> %s : %s", email, code)
				return nil
			}),
			authenticators.WithEmailCodeLength(a.CodeLength),
			authenticators.WithEmailCodeTTL(a.CodeTTL),
		))
	}

	if a := cfg.Authenticators.TempToken; a != nil && a.Enabled {
		store := authenticators.NewMemoryTempTokenStore()
		tt := authenticators.NewTempTokenAuthenticator(store, a.TTL)
		if t, err := tt.Issue(context.Background(), &sso.Subject{ID: "user-bob"}); err == nil {
			log.Printf("[temp_token demo] try: -d '{\"provider\":\"temp_token\",\"credential\":{\"token\":\"%s\"}}'", t)
		}
		auths = append(auths, tt)
	}

	if a := cfg.Authenticators.KeyPair; a != nil && a.Enabled {
		store := authenticators.NewMemoryPublicKeyStore()
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		store.Register(demoKeyID, pub, &sso.Subject{ID: "service-001"})
		auths = append(auths, authenticators.NewKeyPairAuthenticator(store, a.MaxClockSkew))
	}

	if a := cfg.Authenticators.APIKey; a != nil && a.Enabled {
		store := authenticators.NewMemoryAPIKeyStore()
		store.Register(demoAPIKeyID, demoAPISecret, &sso.Subject{ID: "service-demo"})
		auths = append(auths, authenticators.NewAPIKeyAuthenticator(store))
	}

	if a := cfg.Authenticators.Certificate; a != nil && a.Enabled {
		roots := x509.NewCertPool()
		// In production: load a.TrustedCAFiles into roots via x509.NewCertPool().
		auths = append(auths, authenticators.NewCertificateAuthenticator(roots))
	}

	return auths
}
