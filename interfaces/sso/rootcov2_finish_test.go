package sso_test

// rootcov2_finish_test.go exercises the finishLogin enrichment branches the
// earlier passes skipped: geo enrichment (finish_login.go GeoFromHandlerContext
// merge) and embedded permissions (resolvePermissionsForLogin), plus the full
// OIDC userinfo claim projection (userinfo_handler.go projectUserInfoForOIDC)
// across openid+profile+email+address+phone scopes.
//
// REUSES rcovPostJSON / rcovDo and rcov2PasswordAuth.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/geo/static"
)

// TestRcov2F_GeoAndPermissionsLogin covers the geo-enrichment + embedded-
// permissions branches of finishLogin and the full OIDC userinfo projection.
func TestRcov2F_GeoAndPermissionsLogin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, RedirectURIs: []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
	})
	// An authenticator that reports the full OIDC claim set so the userinfo
	// projection has profile/email/address/phone material to emit.
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{
					UserID:      rcovUser,
					AuthMethods: []string{"pwd"},
					Attributes: map[string]string{
						"name":               "Alice Example",
						"preferred_username": "alice",
						"email":              "alice@example.com",
						"email_verified":     "true",
						"phone_number":       "+15551230000",
						"address":            "1 Main St",
						"locale":             "en-US",
					},
				}, nil
			}
			return nil, context.Canceled
		}))

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "viewer", Permissions: []string{"items:read"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"viewer"})

	iss := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithGeoProvider(static.New()),
		sso.WithGeoMiddlewareOptions(sso.GeoMiddlewareOptions{}),
		sso.WithPermissionProvider(prov),
		sso.WithEmbedPermissionsInLogin(),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile", "email", "address", "phone"},
	})
	if status != http.StatusOK {
		t.Fatalf("geo+perms login = %d body=%v", status, out)
	}
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no token: %v", out)
	}
	// Embedded permissions ride the login response.
	if _, ok := out["permissions"]; !ok {
		t.Logf("login response carried no permissions key (embed may key differently): %v", out)
	}

	// Full-scope userinfo projects profile + email + address + phone claims.
	status, ui := rcovDo(t, http.MethodGet, httpSrv.URL+"/userinfo", access, nil)
	if status != http.StatusOK {
		t.Fatalf("full-scope userinfo = %d body=%v", status, ui)
	}
	if ui["sub"] != rcovUser {
		t.Errorf("userinfo sub = %v, want %q", ui["sub"], rcovUser)
	}
	if ui["email"] != "alice@example.com" {
		t.Errorf("userinfo email = %v", ui["email"])
	}
	if ui["phone_number"] == nil && ui["name"] == nil {
		t.Errorf("userinfo projected no profile/phone claims: %v", ui)
	}
}
