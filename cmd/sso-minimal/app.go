package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
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
	opts := serverOptions(cfg, users, passwords, clientStore, issuer)
	opts = append(opts, sso.WithAuthenticator(newOPSessionAuthenticator(sessions)))
	server := sso.NewServer(opts...)
	handler := newOPSessionHandler(server.Handler(), sessions, cfg.Issuer)
	return newPrototypeSurface(handler, configuredScopes(clientSeeds)), nil
}

func serverOptions(
	cfg runtimeConfig,
	users *defaultimpl.MemoryUserProvider,
	passwords *defaultimpl.MemoryPasswordCredentialStore,
	clients *defaultimpl.MemoryClientStore,
	issuer *defaultimpl.Ed25519JWTIssuer,
) []sso.Option {
	return []sso.Option{
		sso.WithIssuer(cfg.Issuer),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(buildPasswordAuthenticator(cfg.User, passwords)),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), authCodeTTL),
		sso.WithOAuth21StrictMode(true),
		sso.WithSupportedSigningAlgs("EdDSA"),
		sso.WithBodyLimit(maxBodyBytes),
		sso.WithMaxTokenBytes(maxTokenBytes),
		sso.WithMaxScopeCount(maxScopeCount),
		sso.WithPanicRecovery(true),
		sso.WithSecurityHeaders(),
		sso.WithFeatureGates(minimalFeatureGates()),
	}
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

func minimalFeatureGates() sso.FeatureGates {
	return sso.FeatureGates{
		OIDC:        sso.Bool(true),
		CIBA:        sso.Bool(false),
		CAEP:        sso.Bool(false),
		Federation:  sso.Bool(false),
		SelfService: sso.Bool(false),
		AdminAPI:    sso.Bool(false),
		WebSPA:      sso.Bool(false),
	}
}
