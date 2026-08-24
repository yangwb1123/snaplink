// Package main demonstrates an SSO server with all 7 authentication methods
// driven by a YAML config file.
package main

import "github.com/yangwb1123/snaplink/shared/spi"

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
	"os"

	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/registry"
	"github.com/yangwb1123/snaplink/platform/registry/memory"
)

// forceRequireMFAScorer is the simplest possible RiskScorer — it
// returns DecisionRequireMFA for every login attempt. Used by the
// MFA_DEMO=1 mode so embedders can exercise the step-up flow
// without setting up a real risk signal. Production embedders
// supply their own RiskScorer with actual risk inputs
// (impossible-travel, device fingerprint, ML scoring); see
// defaultimpl.RuleBasedRiskScorer for a declarative starting
// point.
type forceRequireMFAScorer struct{}

func (forceRequireMFAScorer) Score(_ context.Context, _ *spi.RiskRequest) (*spi.RiskAssessment, error) {
	return &spi.RiskAssessment{Decision: spi.DecisionRequireMFA}, nil
}

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

	opts, err := buildServerOptions(cfg)
	if err != nil {
		log.Fatalf("build server options: %v", err)
	}
	server := sso.NewServer(opts...)
	handler := server.Handler()

	printEndpoints(cfg)
	reg := registerSelf()
	defer func() { _ = reg.Close() }()

	log.Fatal(http.ListenAndServe(cfg.Server.Listen, handler))
}

// buildServerOptions assembles the full option set from config: core wiring
// plus the opt-in audit, permission, authenticator, and MFA-demo blocks.
func buildServerOptions(cfg *config.Config) ([]sso.Option, error) {
	opts := append(cfg.ServerOptions(),
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithTracing("basic"),
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
		sso.WithClientStore(buildClientStore(cfg)),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(cfg.Server.SessionTTL)),
	)

	opts = appendAuditOptions(opts, cfg)
	opts, err := appendPermissionOptions(opts, cfg)
	if err != nil {
		return nil, fmt.Errorf("permissions: %w", err)
	}
	opts = appendAuthenticatorOptions(opts, cfg)
	return opts, nil
}

// buildClientStore seeds an in-memory client store from the config clients.
func buildClientStore(cfg *config.Config) *defaultimpl.MemoryClientStore {
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
	return clientStore
}

// appendAuditOptions wires the memory audit recorder (and optional API) when
// auditing is enabled in config.
func appendAuditOptions(opts []sso.Option, cfg *config.Config) []sso.Option {
	if !cfg.Audit.Enabled {
		return opts
	}
	recorder := audit.New(
		audit.NewMemorySink(cfg.Audit.MemoryCapacity),
		audit.WithErrorHandler(func(err error) { log.Printf("audit: %v", err) }),
	)
	opts = append(opts, sso.WithAuditRecorder(recorder))
	if cfg.Audit.APIEnabled {
		opts = append(opts, sso.WithAuditAPI())
	}
	return opts
}

// appendPermissionOptions wires the permission provider (and optional
// login-embedding) when a provider is configured.
func appendPermissionOptions(opts []sso.Option, cfg *config.Config) ([]sso.Option, error) {
	provider, err := cfg.BuildPermissionProvider()
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return opts, nil
	}
	opts = append(opts, sso.WithPermissionProvider(provider))
	if cfg.Permissions.EmbedInLogin {
		opts = append(opts, sso.WithEmbedPermissionsInLogin())
	}
	return opts, nil
}

// appendAuthenticatorOptions wires the config-enabled authenticators plus the
// TOTP authenticator and the optional MFA_DEMO step-up block.
func appendAuthenticatorOptions(opts []sso.Option, cfg *config.Config) []sso.Option {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	for _, a := range buildAuthenticators(cfg) {
		opts = append(opts, sso.WithAuthenticator(a))
	}
	// TOTP is wired separately so the MFA block below can reuse the
	// same authenticator instance (one user enrollment, two roles —
	// primary auth at /auth/login?provider=totp AND step-up at
	// /auth/mfa). When you don't want the TOTP authenticator for
	// primary auth, drop the WithAuthenticator call here and keep
	// the TOTPMFAProvider wrap below.
	opts = append(opts, sso.WithAuthenticator(totpAuth))

	// MFA orchestration reference wiring. Reads MFA_DEMO=1 from the
	// environment so the default example flow stays simple. Embedders
	// shipping MFA in production wire WithRiskScorer with their real
	// scorer (impossible-travel, device fingerprint, etc) and let
	// THAT decide DecisionRequireMFA per request rather than the
	// blanket force-on stub used here.
	if os.Getenv("MFA_DEMO") == "1" {
		opts = append(opts,
			sso.WithRiskScorer(forceRequireMFAScorer{}),
			sso.WithMFAProvider(authenticators.NewTOTPMFAProvider(totpAuth)),
			sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 0),
		)
		log.Printf("MFA_DEMO=1 — every login goes through TOTP step-up")
	}
	return opts
}

// printEndpoints lists the live endpoints, branching on the audit and
// permission features that were enabled in config.
func printEndpoints(cfg *config.Config) {
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
}

// registerSelf registers this instance in an in-memory service registry and
// returns it so main can defer Close. Swap memory.New() for etcd.New(...)
// when you have an etcd cluster.
func registerSelf() *memory.Registry {
	reg := memory.New()
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
	return reg
}

// buildAuthenticators returns the enabled set of authenticators based on the
// config. Code-only inputs (verifiers, senders, key material) are wired here.
func buildAuthenticators(cfg *config.Config) []sso.Authenticator {
	var auths []sso.Authenticator
	codeStore := authenticators.NewMemoryCodeStore()

	if a := cfg.Authenticators.Password; a != nil && a.Enabled {
		auths = append(auths, buildPasswordAuth())
	}
	if a := cfg.Authenticators.Phone; a != nil && a.Enabled {
		auths = append(auths, buildPhoneAuth(codeStore, a))
	}
	if a := cfg.Authenticators.Email; a != nil && a.Enabled {
		auths = append(auths, buildEmailAuth(codeStore, a))
	}
	if a := cfg.Authenticators.TempToken; a != nil && a.Enabled {
		auths = append(auths, buildTempTokenAuth(a))
	}
	if a := cfg.Authenticators.KeyPair; a != nil && a.Enabled {
		auths = append(auths, buildKeyPairAuth(a))
	}
	if a := cfg.Authenticators.APIKey; a != nil && a.Enabled {
		auths = append(auths, buildAPIKeyAuth())
	}
	if a := cfg.Authenticators.Certificate; a != nil && a.Enabled {
		auths = append(auths, buildCertificateAuth())
	}

	return auths
}

func buildPasswordAuth() sso.Authenticator {
	return authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, user, pass string) (*sso.AuthResult, error) {
			if user == demoUser && pass == demoPassword {
				return &sso.AuthResult{UserID: "user-" + user, ExternalID: user}, nil
			}
			return nil, errors.New("bad credentials")
		}),
	)
}

func buildPhoneAuth(codeStore authenticators.CodeStore, a *config.PhoneConfig) sso.Authenticator {
	return authenticators.NewPhoneAuthenticator(
		codeStore,
		authenticators.SMSSenderFunc(func(_ context.Context, phone, code string) error {
			log.Printf("[sms stub] -> %s : %s", phone, code)
			return nil
		}),
		authenticators.WithPhoneCodeLength(a.CodeLength),
		authenticators.WithPhoneCodeTTL(a.CodeTTL),
	)
}

func buildEmailAuth(codeStore authenticators.CodeStore, a *config.CodeAuthConfig) sso.Authenticator {
	return authenticators.NewEmailAuthenticator(
		codeStore,
		authenticators.EmailSenderFunc(func(_ context.Context, email, code string) error {
			log.Printf("[email stub] -> %s : %s", email, code)
			return nil
		}),
		authenticators.WithEmailCodeLength(a.CodeLength),
		authenticators.WithEmailCodeTTL(a.CodeTTL),
	)
}

func buildTempTokenAuth(a *config.TempTokenConfig) sso.Authenticator {
	store := authenticators.NewMemoryTempTokenStore()
	tt := authenticators.NewTempTokenAuthenticator(store, a.TTL)
	if t, err := tt.Issue(context.Background(), &sso.Subject{ID: "user-bob"}); err == nil {
		log.Printf("[temp_token demo] try: -d '{\"provider\":\"temp_token\",\"credential\":{\"token\":\"%s\"}}'", t)
	}
	return tt
}

func buildKeyPairAuth(a *config.KeyPairConfig) sso.Authenticator {
	store := authenticators.NewMemoryPublicKeyStore()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	store.Register(demoKeyID, pub, &sso.Subject{ID: "service-001"})
	return authenticators.NewKeyPairAuthenticator(store, a.MaxClockSkew)
}

func buildAPIKeyAuth() sso.Authenticator {
	store := authenticators.NewMemoryAPIKeyStore()
	store.Register(demoAPIKeyID, demoAPISecret, &sso.Subject{ID: "service-demo"})
	return authenticators.NewAPIKeyAuthenticator(store)
}

func buildCertificateAuth() sso.Authenticator {
	roots := x509.NewCertPool()
	// In production: load a.TrustedCAFiles into roots via x509.NewCertPool().
	return authenticators.NewCertificateAuthenticator(roots)
}
