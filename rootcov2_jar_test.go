package sso_test

// rootcov2_jar_test.go drives the RFC 9101 JAR (signed request object) path
// (jar_security.go verifyJAR) and the tenant-suspension gate
// (server_extensions.go checkTenantNotSuspended + InvalidateTenantSuspensionCache)
// the first rootcov_* pass left at 0%.
//
// The JAR request object is a real Ed25519-signed JWS verified against the
// client's registered JWKS. REUSES rcov2NewDPoPKey + the rcov* HTTP helpers.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	tenantpkg "github.com/snaplink/sso/tenant"
	tenantmem "github.com/snaplink/sso/tenant/memory"
)

const rcov2JARIssuer = "https://rcov2-jar.example.com"

// rcov2SignJAR builds a JAR request object JWT signed by key for the given
// client, carrying authorization params + aud=audience.
func rcov2SignJAR(t *testing.T, key rcov2DPoPKey, kid, clientID, audience, redirect string) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "oauth-authz-req+jwt", "kid": kid}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	payload := map[string]any{
		"iss":           clientID,
		"client_id":     clientID,
		"aud":           audience,
		"response_type": "code",
		"redirect_uri":  redirect,
		"scope":         "openid",
		"state":         "jar-state",
		"exp":           time.Now().Add(time.Minute).Unix(),
		"iat":           time.Now().Unix(),
		"jti":           base64.RawURLEncoding.EncodeToString(jti),
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(key.priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestRcov2J_SignedRequestObject covers the JAR `request` parameter on
// /auth/login: a signed request object is verified against the client JWKS and
// its parameters drive the authorization (verifyJAR).
func TestRcov2J_SignedRequestObject(t *testing.T) {
	key := rcov2NewDPoPKey(t)
	const kid = "jar-key-1"
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, RedirectURIs: []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
		JWKS: []sso.JWK{{
			Kty: "OKP", Crv: "Ed25519", Kid: kid,
			X: base64.RawURLEncoding.EncodeToString(key.pub),
		}},
	})
	iss := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithIssuer(rcov2JARIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithJTIReplayStore(defaultimpl.NewMemoryJTIReplayStore()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// aud MUST be the configured issuer.
	request := rcov2SignJAR(t, key, kid, rcovClient, rcov2JARIssuer, rcovRedirect)
	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"request":    request,
	})
	if status != http.StatusOK {
		t.Fatalf("JAR login = %d body=%v", status, out)
	}
	// The signed request carried response_type=code => a code is minted, and
	// the state from the JAR is echoed.
	if out["code"] == "" || out["code"] == nil {
		t.Errorf("JAR login minted no code: %v", out)
	}
	if out["state"] != "jar-state" {
		t.Errorf("JAR state = %v, want jar-state (from the signed object)", out["state"])
	}

	// A JAR with the wrong audience is rejected (invalid_request_object).
	badAud := rcov2SignJAR(t, key, kid, rcovClient, "https://wrong.example.com", rcovRedirect)
	status, out = rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"request":    badAud,
	})
	if status != http.StatusBadRequest {
		t.Errorf("JAR wrong aud = %d, want 400 (body=%v)", status, out)
	}

	// A JAR signed by a foreign key fails signature verification.
	foreign := rcov2SignJAR(t, rcov2NewDPoPKey(t), kid, rcovClient, rcov2JARIssuer, rcovRedirect)
	status, _ = rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"request":    foreign,
	})
	if status != http.StatusBadRequest {
		t.Errorf("JAR forged signature = %d, want 400", status)
	}
}

// TestRcov2J_TenantSuspension covers the tenant-suspension gate, which fires at
// token-VALIDATION time (the post-validation gate): a token bound to a client of
// a suspended tenant is rejected at /userinfo; reactivating + invalidating the
// cache restores access (checkTenantNotSuspended + InvalidateTenantSuspensionCache).
func TestRcov2J_TenantSuspension(t *testing.T) {
	ctx := context.Background()
	tstore := tenantmem.New()
	// Start ACTIVE so the token mints; suspension is applied AFTER issuance.
	_ = tstore.PutTenant(ctx, &tenantpkg.Tenant{
		ID: "susp-org", Slug: "susp-org", Name: "Org", Status: tenantpkg.StatusActive,
	})

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
		TenantID: "susp-org",
	})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantStore(tstore),
		sso.WithTenantSuspensionCheck(time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Mint a token while the tenant is active.
	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("active-tenant login = %d body=%v", status, out)
	}
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no token: %v", out)
	}

	// Token works while active.
	status, _ = rcovDo(t, http.MethodGet, httpSrv.URL+"/userinfo", access, nil)
	if status != http.StatusOK {
		t.Fatalf("active-tenant userinfo = %d, want 200", status)
	}

	// Suspend the tenant + invalidate the cache so the gate sees it.
	_ = tstore.PutTenant(ctx, &tenantpkg.Tenant{
		ID: "susp-org", Slug: "susp-org", Name: "Org", Status: tenantpkg.StatusSuspended,
	})
	srv.InvalidateTenantSuspensionCache("susp-org")

	// The token is now rejected (suspended tenant).
	status, _ = rcovDo(t, http.MethodGet, httpSrv.URL+"/userinfo", access, nil)
	if status == http.StatusOK {
		t.Errorf("suspended-tenant userinfo = 200, want rejected")
	}

	// Reactivate + invalidate => access restored.
	_ = tstore.PutTenant(ctx, &tenantpkg.Tenant{
		ID: "susp-org", Slug: "susp-org", Name: "Org", Status: tenantpkg.StatusActive,
	})
	srv.InvalidateTenantSuspensionCache("susp-org")
	status, _ = rcovDo(t, http.MethodGet, httpSrv.URL+"/userinfo", access, nil)
	if status != http.StatusOK {
		t.Errorf("reactivated-tenant userinfo = %d, want 200", status)
	}
}
