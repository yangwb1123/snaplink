package ssotest

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	refProcessConfigEnv = "SNAPLINK_REFERENCE_PROCESS_CONFIG"
	refProcessReadyEnv  = "SNAPLINK_REFERENCE_PROCESS_READY"
)

type refProcessConfig struct {
	DSN, Issuer            string
	SigningSeed, LookupKey []byte
}

type refProcessReady struct {
	PID int
	URL string
}

type refProcessStores struct {
	db        *sql.DB
	users     *postgres.UserProvider
	passwords *postgres.PasswordCredentialStore
	clients   *postgres.ClientStore
	tenants   *postgres.TenantStore
	sessions  *postgres.SessionManager
	codes     *postgres.AuthCodeStore
	refresh   *postgres.RefreshTokenStore
}

func refProcessCheck(t *testing.T, err error, operation string) {
	t.Helper()
	if err != nil {
		t.Fatal(operation + " failed (sensitive backend diagnostics omitted)")
	}
}

func newRefProcessStores(t *testing.T, dsn string) *refProcessStores {
	t.Helper()
	s := &refProcessStores{}
	var err error
	s.db, err = postgres.Open(postgres.Config{DSN: dsn, MaxOpenConns: 8, MaxIdleConns: 2})
	refProcessCheck(t, err, "open reference PostgreSQL pool")
	t.Cleanup(func() {
		_ = s.codes.Close()
		_ = s.refresh.Close()
		_ = s.db.Close()
	})
	dialect := postgres.DialectPostgres
	s.users, err = postgres.NewUserProviderWithDB(s.db, dialect)
	refProcessCheck(t, err, "open shared users")
	s.passwords, err = postgres.NewPasswordCredentialStoreWithDB(s.db, dialect)
	refProcessCheck(t, err, "open shared passwords")
	s.clients, err = postgres.NewClientStoreWithDB(s.db, dialect)
	refProcessCheck(t, err, "open shared clients")
	s.tenants, err = postgres.NewTenantStoreWithDB(s.db, dialect)
	refProcessCheck(t, err, "open shared tenants")
	s.sessions, err = postgres.NewSessionManagerWithDB(s.db, dialect, time.Hour)
	refProcessCheck(t, err, "open shared sessions")
	s.codes, err = postgres.NewAuthCodeStoreWithDB(s.db, dialect)
	refProcessCheck(t, err, "open shared authorization codes")
	s.refresh, err = postgres.NewRefreshTokenStoreWithDB(s.db, dialect)
	refProcessCheck(t, err, "open shared refresh tokens")
	return s
}

func (s *refProcessStores) seed(t *testing.T) map[string]refAppClient {
	t.Helper()
	bindings := map[string]refAppClient{}
	for _, tenantID := range refTenantIDs {
		refProcessCheck(t, s.tenants.PutTenant(t.Context(), &tenant.Tenant{ID: tenantID, Slug: tenantID, Name: tenantID}), "seed reference tenant")
		refProcessCheck(t, s.tenants.PutDomain(t.Context(), &tenant.Domain{Hostname: tenantID + ".example.test", TenantID: tenantID}), "seed reference domain")
		refProcessCheck(t, s.users.CreateOrUpdate(t.Context(), &sso.User{ID: "user-" + tenantID}), "seed reference user")
		refProcessCheck(t, s.passwords.SetPassword(t.Context(), "user-"+tenantID, refAppPassword), "seed reference password")
		for _, app := range refAppNames {
			id := app + "-" + tenantID
			binding := refAppClient{App: app, Tenant: tenantID, ID: id, Secret: "fixture-only-" + id, Redirect: "https://" + id + ".example.test/callback", Scope: app + ":read", Audience: app + "-api"}
			bindings[app+"/"+tenantID] = binding
			refProcessCheck(t, s.clients.Put(t.Context(), &sso.Client{ID: id, Secret: binding.Secret, Name: id, TenantID: tenantID, Active: true, TokenStrategy: "jwt",
				TokenEndpointAuthMethod: "client_secret_basic", GrantTypes: []string{"authorization_code", "refresh_token"},
				AllowedScopes: []string{"openid", binding.Scope}, AllowedResources: []string{binding.Audience},
				AllowedAuthenticators: []string{"password"}, RedirectURIs: []string{binding.Redirect}, SkipConsent: true,
				RequirePKCE: true, AllowedPKCEMethods: []string{"S256"}}), "seed reference client")
		}
	}
	return bindings
}

// Only the parent seeds. Restarted children must consume existing durable state,
// not recreate credentials, sessions, codes or refresh-family evidence.
func TestReferenceProcessChild(t *testing.T) {
	path := os.Getenv(refProcessConfigEnv)
	if path == "" {
		return
	}
	file, err := os.Open(path)
	refProcessCheck(t, err, "open private child configuration")
	var cfg refProcessConfig
	err = json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(&cfg)
	_ = file.Close()
	refProcessCheck(t, err, "decode private child configuration")
	if len(cfg.SigningSeed) != ed25519.SeedSize || len(cfg.LookupKey) != 32 || cfg.Issuer == "" {
		t.Fatal("invalid reference child key/origin configuration")
	}
	stores := newRefProcessStores(t, cfg.DSN)
	stores.codes.SetLookupHMACKeys(cfg.LookupKey)
	stores.refresh.SetLookupHMACKeys(cfg.LookupKey)
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Key(ed25519.NewKeyFromSeed(cfg.SigningSeed)),
		defaultimpl.WithEd25519Issuer(cfg.Issuer), defaultimpl.WithEd25519TokenTTL(10*time.Minute))
	stored := authenticators.NewStoredPasswordVerifier(stores.passwords, func(ctx context.Context, username string) (string, error) {
		user, err := stores.users.GetByID(ctx, username) // Fixture usernames are canonical user IDs.
		if err != nil {
			return "", err
		}
		return user.ID, nil
	})
	password := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(func(ctx context.Context, username, credential string) (*sso.AuthResult, error) {
		result, err := stored.Verify(ctx, username, credential)
		if err == nil {
			result.CreateSession = true
		}
		return result, err
	}))
	server := sso.NewServer(sso.WithIssuer(cfg.Issuer), sso.WithUserProvider(stores.users), sso.WithClientStore(stores.clients),
		sso.WithTenantStore(stores.tenants), sso.WithSessionManager(stores.sessions), sso.WithAuthCodeStore(stores.codes, time.Minute),
		sso.WithRefreshTokenStore(stores.refresh, time.Hour), sso.WithAuthenticator(password), sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer), sso.WithDefaultTokenStrategy("jwt"), sso.WithBrowserSSO(issuer, issuer))
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close) // HTTP drains before the underlying caller-owned pool closes.
	ready, err := json.Marshal(refProcessReady{PID: os.Getpid(), URL: httpServer.URL})
	refProcessCheck(t, err, "encode child readiness")
	refProcessCheck(t, os.WriteFile(os.Getenv(refProcessReadyEnv), ready, 0o600), "write child readiness")
	_, err = io.Copy(io.Discard, os.Stdin) // EOF is the parent's graceful-stop signal.
	refProcessCheck(t, err, "wait for parent stop")
}
