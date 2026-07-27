package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	authCodeTTL   = 5 * time.Minute
	tokenTTL      = time.Hour
	maxBodyBytes  = 1 << 20
	maxTokenBytes = 16 << 10
	maxScopeCount = 32
)

func buildHandler(cfg runtimeConfig) (http.Handler, error) {
	return buildHandlerWithClients(cfg, []clientSeed{cfg.Second})
}

func buildHandlerWithClients(cfg runtimeConfig, extraClients []clientSeed) (http.Handler, error) {
	return buildHandlerWithSessions(
		cfg,
		extraClients,
		newOPSessionStore(cfg.User),
	)
}

func buildHandlerWithSessions(
	cfg runtimeConfig,
	extraClients []clientSeed,
	sessions *opSessionStore,
) (http.Handler, error) {
	users := defaultimpl.NewMemoryUserProvider()
	passwords := defaultimpl.NewMemoryPasswordCredentialStore()
	if err := seedUser(context.Background(), users, passwords, cfg.User); err != nil {
		return nil, err
	}
	clientSeeds := append([]clientSeed{cfg.Client}, extraClients...)
	clientStore := defaultimpl.NewMemoryClientStore()
	for _, client := range clientSeeds {
		clientStore.AddSeed(seedClient(client))
	}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(tokenTTL))
	tenantStore, err := newDefaultTenantStore(context.Background())
	if err != nil {
		return nil, err
	}
	opts := serverOptions(cfg, users, passwords, clientStore, issuer, tenantStore)
	opts = append(opts, sso.WithAuthenticator(newOPSessionAuthenticator(sessions)))
	server := sso.NewServer(opts...)
	handler := newOPSessionHandler(server.Handler(), sessions, cfg.Issuer)
	return newPrototypeSurface(
		handler,
		configuredScopes(clientSeeds),
		cfg.Edition,
	), nil
}

func serverOptions(
	cfg runtimeConfig,
	users *defaultimpl.MemoryUserProvider,
	passwords *defaultimpl.MemoryPasswordCredentialStore,
	clients *defaultimpl.MemoryClientStore,
	issuer *defaultimpl.Ed25519JWTIssuer,
	tenantStore tenant.Store,
) []sso.Option {
	opts := []sso.Option{
		sso.WithIssuer(cfg.Issuer),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(buildPasswordAuthenticator(cfg.User, passwords)),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), authCodeTTL),
		sso.WithOAuth21StrictMode(true),
		sso.WithSupportedSigningAlgs("EdDSA"),
		sso.WithBodyLimit(maxBodyBytes),
		sso.WithMaxTokenBytes(maxTokenBytes),
		sso.WithMaxScopeCount(maxScopeCount),
		sso.WithPanicRecovery(true),
		sso.WithSecurityHeaders(),
		sso.WithLogger(newJSONLogger(os.Stderr)),
		sso.WithTenantStore(tenantStore),
		sso.WithFeatureGates(featureGatesForEdition(cfg.Edition)),
	}
	if cfg.Edition.oidcEnabled() {
		opts = append(opts, sso.WithIDTokenIssuer(issuer))
	}
	if cfg.Edition.tracingEnabled() {
		opts = append(opts, sso.WithTracingMiddleware())
	}
	return opts
}

func seedUser(
	ctx context.Context,
	users *defaultimpl.MemoryUserProvider,
	passwords *defaultimpl.MemoryPasswordCredentialStore,
	seed userSeed,
) error {
	user := &sso.User{
		ID:          seed.ID,
		Username:    seed.Username,
		Email:       seed.Email,
		DisplayName: seed.DisplayName,
	}
	if err := users.CreateOrUpdate(ctx, user); err != nil {
		return err
	}
	return passwords.SetPassword(ctx, seed.ID, seed.Password)
}

func seedClient(seed clientSeed) *sso.Client {
	return &sso.Client{
		ID:                    seed.ID,
		Secret:                seed.Secret,
		Name:                  seed.ID,
		RedirectURIs:          []string{seed.RedirectURI},
		AllowedScopes:         append([]string(nil), seed.Scopes...),
		AllowedAuthenticators: []string{authenticators.MethodPassword, opSessionProvider},
		TokenStrategy:         "jwt",
		TenantID:              defaultTenantID,
		Active:                true,
		RequirePKCE:           true,
		AllowedPKCEMethods:    []string{sso.PKCEMethodS256},
		SkipConsent:           true,
	}
}

func buildPasswordAuthenticator(
	seed userSeed,
	passwords *defaultimpl.MemoryPasswordCredentialStore,
) sso.Authenticator {
	resolve := func(_ context.Context, username string) (string, error) {
		if !strings.EqualFold(username, seed.Username) {
			return "", errors.New("unknown user")
		}
		return seed.ID, nil
	}
	base := authenticators.NewStoredPasswordVerifier(passwords, resolve)
	verifier := authenticators.PasswordVerifierFunc(func(ctx context.Context, username, password string) (*sso.AuthResult, error) {
		result, err := base.Verify(ctx, username, password)
		if err != nil {
			return nil, err
		}
		result.ExternalID = seed.Username
		result.Attributes = userClaims(seed)
		return result, nil
	})
	return authenticators.NewPasswordAuthenticator(verifier)
}

func userClaims(seed userSeed) map[string]string {
	claims := map[string]string{"preferred_username": seed.Username}
	if seed.Email != "" {
		claims["email"] = seed.Email
	}
	if seed.DisplayName != "" {
		claims["name"] = seed.DisplayName
	}
	return claims
}

func featureGatesForEdition(edition runtimeEdition) sso.FeatureGates {
	return sso.FeatureGates{
		OIDC:        sso.Bool(edition.oidcEnabled()),
		CIBA:        sso.Bool(false),
		CAEP:        sso.Bool(false),
		Federation:  sso.Bool(false),
		SelfService: sso.Bool(false),
		AdminAPI:    sso.Bool(false),
		WebSPA:      sso.Bool(false),
	}
}

func newDefaultTenantStore(ctx context.Context) (tenant.Store, error) {
	store := tenantmemory.New()
	err := store.PutTenant(ctx, &tenant.Tenant{
		ID:     defaultTenantID,
		Slug:   defaultTenantID,
		Name:   "Default",
		Status: tenant.StatusActive,
	})
	if err != nil {
		return nil, err
	}
	return store, nil
}
