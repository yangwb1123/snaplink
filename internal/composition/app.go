package composition

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
	MaxBodyBytes  = 1 << 20
	maxTokenBytes = 16 << 10
	maxScopeCount = 32
)

// SurfaceHooks carry the edition-specific surface behavior into the shared
// envelope: which metadata path is served, which routes are allowed, and how
// the discovery document is narrowed. The minimal edition's hooks reference
// the OIDC surface; the prototype edition's hooks reference none of it.
type SurfaceHooks struct {
	IsMetadata func(path string) bool
	Allowed    func(method, path string) bool
	Narrow     func(document map[string]any)
}

// BuildOptions parameterize BuildHandler with the edition's extra clients,
// session gate, OIDC/tracing option hook, and surface hooks.
type BuildOptions struct {
	ExtraClients []ClientSeed
	SessionGate  *OpSessionGate
	ExtraOptions func(*defaultimpl.Ed25519JWTIssuer) []sso.Option
	Surface      SurfaceHooks
}

// BuildHandler assembles the small-edition server: memory stores, the seeded
// user and clients, the Ed25519 JWT issuer, the canonical OP-session gate, and
// the edition surface envelope.
func BuildHandler(cfg RuntimeConfig, opts BuildOptions) (http.Handler, error) {
	users := defaultimpl.NewMemoryUserProvider()
	passwords := defaultimpl.NewMemoryPasswordCredentialStore()
	if err := seedUser(context.Background(), users, passwords, cfg.User); err != nil {
		return nil, err
	}
	clientSeeds := append([]ClientSeed{cfg.Client}, opts.ExtraClients...)
	clientStore := defaultimpl.NewMemoryClientStore()
	for _, client := range clientSeeds {
		clientStore.AddSeed(seedClient(client))
	}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(tokenTTL))
	tenantStore, err := newDefaultTenantStore(context.Background())
	if err != nil {
		return nil, err
	}
	gate := opts.SessionGate
	if gate == nil {
		gate = NewOPSessionGate()
	}
	serverOpts := serverOptions(cfg, users, passwords, clientStore, issuer, tenantStore, opts.ExtraOptions)
	serverOpts = append(serverOpts, sso.WithAuthenticator(newOPSessionAuthenticator(gate, cfg.User)))
	server := sso.NewServer(serverOpts...)
	gate.SetMgr(server.SessionMgr())
	handler := newOPSessionHandler(server.Handler(), gate, cfg.Issuer)
	return NewSurface(handler, ConfiguredScopes(clientSeeds), opts.Surface), nil
}

func serverOptions(
	cfg RuntimeConfig,
	users *defaultimpl.MemoryUserProvider,
	passwords *defaultimpl.MemoryPasswordCredentialStore,
	clients *defaultimpl.MemoryClientStore,
	issuer *defaultimpl.Ed25519JWTIssuer,
	tenantStore tenant.Store,
	extra func(*defaultimpl.Ed25519JWTIssuer) []sso.Option,
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
		sso.WithBodyLimit(MaxBodyBytes),
		sso.WithMaxTokenBytes(maxTokenBytes),
		sso.WithMaxScopeCount(maxScopeCount),
		sso.WithPanicRecovery(true),
		sso.WithSecurityHeaders(),
		sso.WithLogger(newJSONLogger(os.Stderr)),
		sso.WithTenantStore(tenantStore),
		sso.WithFeatureGates(featureGatesForEdition(cfg.Edition)),
	}
	if extra != nil {
		opts = append(opts, extra(issuer)...)
	}
	return opts
}

func seedUser(
	ctx context.Context,
	users *defaultimpl.MemoryUserProvider,
	passwords *defaultimpl.MemoryPasswordCredentialStore,
	seed UserSeed,
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

func seedClient(seed ClientSeed) *sso.Client {
	return &sso.Client{
		ID:                    seed.ID,
		Secret:                seed.Secret,
		Name:                  seed.ID,
		RedirectURIs:          []string{seed.RedirectURI},
		AllowedScopes:         append([]string(nil), seed.Scopes...),
		AllowedAuthenticators: []string{authenticators.MethodPassword, opSessionProvider},
		TokenStrategy:         "jwt",
		TenantID:              DefaultTenantID,
		Active:                true,
		RequirePKCE:           true,
		AllowedPKCEMethods:    []string{sso.PKCEMethodS256},
		SkipConsent:           true,
	}
}

func buildPasswordAuthenticator(
	seed UserSeed,
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
		// A successful password login starts a canonical OP session: the
		// code flow mints the session, the response returns session_id, and
		// the browser cookie binds to it — prompt=none / max_age resume
		// then works against the canonical SessionManager, not a parallel
		// edition-local store.
		result.CreateSession = true
		return result, nil
	})
	return authenticators.NewPasswordAuthenticator(verifier)
}

func userClaims(seed UserSeed) map[string]string {
	claims := map[string]string{"preferred_username": seed.Username}
	if seed.Email != "" {
		claims["email"] = seed.Email
	}
	if seed.DisplayName != "" {
		claims["name"] = seed.DisplayName
	}
	return claims
}

func featureGatesForEdition(edition Edition) sso.FeatureGates {
	return sso.FeatureGates{
		OIDC:        sso.Bool(edition.OIDC),
		CIBA:        sso.Bool(false),
		CAEP:        sso.Bool(false),
		Federation:  sso.Bool(false),
		SelfService: sso.Bool(false),
		AdminAPI:    sso.Bool(false),
		Branding:    sso.Bool(false),
	}
}

// NewDefaultTenantStore returns the stable "default" tenant migration anchor
// used by both small editions.
func NewDefaultTenantStore(ctx context.Context) (tenant.Store, error) {
	store := tenantmemory.New()
	err := store.PutTenant(ctx, &tenant.Tenant{
		ID:     DefaultTenantID,
		Slug:   DefaultTenantID,
		Name:   "Default",
		Status: tenant.StatusActive,
	})
	if err != nil {
		return nil, err
	}
	return store, nil
}

func newDefaultTenantStore(ctx context.Context) (tenant.Store, error) {
	return NewDefaultTenantStore(ctx)
}

// DefaultTenantID is the stable default tenant used by the small editions.
const DefaultTenantID = "default"
