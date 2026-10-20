package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
)

const refAppPassword = "fixture-only-password-not-for-deployment"
const refAppRole = "reader"

var refAppNames = []string{"orders", "reports"}
var refTenantIDs = []string{"tenant-a", "tenant-b"}

type refAppClient struct {
	App, Tenant, ID, Secret, Redirect, Scope, Audience string
}

type referenceApps struct {
	base          string
	http          *httptest.Server
	server        *sso.Server
	issuer        *defaultimpl.Ed25519JWTIssuer
	clients       map[string]refAppClient
	browsers      map[string]*http.Client
	apis          map[string]*httptest.Server
	cache         *rs.JWKSCache
	permissions   *permissions.MemoryProvider
	passwordCalls atomic.Int64
}

func newReferenceApps(t *testing.T) *referenceApps {
	t.Helper()
	h := &referenceApps{http: httptest.NewUnstartedServer(nil), clients: map[string]refAppClient{}, browsers: map[string]*http.Client{}, apis: map[string]*httptest.Server{}, permissions: permissions.NewMemoryProvider()}
	t.Cleanup(h.http.Close)
	h.base = "http://" + h.http.Listener.Addr().String()
	h.issuer = defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(h.base), defaultimpl.WithEd25519TokenTTL(10*time.Minute))
	users := defaultimpl.NewMemoryUserProvider()
	passwords := defaultimpl.NewMemoryPasswordCredentialStore()
	clients := defaultimpl.NewMemoryClientStore()
	tenants := tenantmemory.New()
	h.seedReferenceApps(t, users, passwords, clients, tenants)
	stored := authenticators.NewStoredPasswordVerifier(passwords, func(ctx context.Context, username string) (string, error) {
		u, err := users.GetByUsername(ctx, username)
		if err != nil {
			return "", err
		}
		return u.ID, nil
	})
	password := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(func(ctx context.Context, username, credential string) (*sso.AuthResult, error) {
		h.passwordCalls.Add(1)
		result, err := stored.Verify(ctx, username, credential)
		if err == nil {
			result.CreateSession = true
		}
		return result, err
	}))
	sessions, codes, refresh := defaultimpl.NewMemorySessionManager(), defaultimpl.NewMemoryAuthCodeStore(), defaultimpl.NewMemoryRefreshTokenStore()
	for _, closer := range []io.Closer{sessions, codes, refresh} {
		t.Cleanup(func() { _ = closer.Close() })
	}
	h.server = sso.NewServer(sso.WithIssuer(h.base), sso.WithUserProvider(users), sso.WithClientStore(clients), sso.WithTenantStore(tenants),
		sso.WithSessionManager(sessions), sso.WithAuthCodeStore(codes, time.Minute), sso.WithRefreshTokenStore(refresh, time.Hour),
		sso.WithAuthenticator(password), sso.WithTokenIssuer("jwt", h.issuer), sso.WithIDTokenIssuer(h.issuer), sso.WithDefaultTokenStrategy("jwt"),
		sso.WithBrowserSSO(h.issuer, h.issuer), sso.WithPermissionProvider(h.permissions))
	h.http.Config.Handler = h.server.Handler()
	h.http.Start()
	h.cache = rs.NewJWKSCache(h.base+core.PathJWKS, remote.WithJWKSHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	t.Cleanup(h.cache.Close)
	for _, app := range refAppNames {
		mux := http.NewServeMux()
		for _, tenantID := range refTenantIDs {
			binding := h.clients[app+"/"+tenantID]
			for _, mode := range []string{"online", "offline"} {
				cfg := rs.Config{Issuer: h.base, ExpectedAud: binding.Audience, AllowedAlgs: []string{"EdDSA"}, JWKSCache: h.cache}
				if mode == "online" {
					cfg.IntrospectURL, cfg.IntrospectCreds = h.base+core.PathIntrospect, &rs.ClientCreds{ID: binding.ID, Secret: binding.Secret}
				}
				mux.Handle("GET /"+mode+"/"+tenantID, rs.HTTPMiddleware(cfg, h.referenceResource(binding)))
			}
		}
		h.apis[app] = httptest.NewServer(mux)
		t.Cleanup(h.apis[app].Close)
	}
	return h
}

func (h *referenceApps) seedReferenceApps(t *testing.T, users *defaultimpl.MemoryUserProvider, passwords *defaultimpl.MemoryPasswordCredentialStore, clients *defaultimpl.MemoryClientStore, tenants tenant.Store) {
	t.Helper()
	ctx := t.Context()
	for _, tenantID := range refTenantIDs {
		if err := tenants.PutTenant(ctx, &tenant.Tenant{ID: tenantID, Slug: tenantID, Name: tenantID}); err != nil {
			t.Fatal(err)
		}
		if err := tenants.PutDomain(ctx, &tenant.Domain{Hostname: tenantID + ".example.test", TenantID: tenantID}); err != nil {
			t.Fatal(err)
		}
		if err := users.CreateOrUpdate(ctx, &sso.User{ID: "user-" + tenantID, Username: "user-" + tenantID}); err != nil {
			t.Fatal(err)
		}
		if err := passwords.SetPassword(ctx, "user-"+tenantID, refAppPassword); err != nil {
			t.Fatal("seed fixture password")
		}
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		h.browsers[tenantID] = &http.Client{Jar: jar, Timeout: 5 * time.Second}
		for _, app := range refAppNames {
			id := app + "-" + tenantID
			binding := refAppClient{App: app, Tenant: tenantID, ID: id, Secret: "fixture-only-" + id, Redirect: "https://" + id + ".example.test/callback", Scope: app + ":read", Audience: app + "-api"}
			h.clients[app+"/"+tenantID] = binding
			clients.AddSeed(&sso.Client{ID: id, Secret: binding.Secret, Name: id, TenantID: tenantID, Active: true, TokenStrategy: "jwt",
				TokenEndpointAuthMethod: "client_secret_basic", GrantTypes: []string{"authorization_code", "refresh_token"},
				AllowedScopes: []string{"openid", binding.Scope}, AllowedResources: []string{binding.Audience},
				AllowedAuthenticators: []string{"password"}, RedirectURIs: []string{binding.Redirect}, SkipConsent: true,
				RequirePKCE: true, AllowedPKCEMethods: []string{"S256"}})
			if err := h.permissions.AddRole(ctx, id, permissions.Role{Code: refAppRole, Permissions: []string{binding.Scope}}); err != nil {
				t.Fatal(err)
			}
			if err := h.permissions.AssignRoles(ctx, "user-"+tenantID, id, []string{refAppRole}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// The resource and client binding are server-side route configuration, not
// an unverified token payload or browser-supplied tenant header.
func (h *referenceApps) referenceResource(binding refAppClient) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := rs.ClaimsFromContext(r.Context())
		if !ok || claims.TenantID != binding.Tenant {
			refAppJSON(w, http.StatusForbidden, map[string]any{"error": core.ErrTenantMismatch})
			return
		}
		if claims.ClientID != binding.ID || !slices.Contains(claims.Scopes(), binding.Scope) {
			refAppJSON(w, http.StatusForbidden, map[string]any{"error": "insufficient_scope"})
			return
		}
		perms, err := h.permissions.Permissions(r.Context(), claims.Subject, binding.ID)
		if err != nil || !slices.ContainsFunc(perms, func(p permissions.Permission) bool { return p.Code == binding.Scope }) {
			refAppJSON(w, http.StatusForbidden, map[string]any{"error": "permission_denied"})
			return
		}
		refAppJSON(w, http.StatusOK, map[string]any{"app": binding.App, "tenant": binding.Tenant, "user": claims.Subject, "items": []string{binding.Tenant + "-" + binding.App + "-row"}})
	})
}

func refAppJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
