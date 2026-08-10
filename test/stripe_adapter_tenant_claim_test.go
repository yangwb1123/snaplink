package ssotest

// Stripe-adapter tenant-claim e2e (T-9, A11-A13): the /token-minted
// tenant_id claim (B4-1 mint, stamped from the client binding) must survive
// mint -> signature validation -> claims projection through the PRODUCTION
// rs components the adapter mounts (JWKS cache + HTTPMiddleware with the
// adapter's config shape). The adapter's own gate logic is pinned at unit
// level (cmd/snaplink-stripe-adapter/http_test.go — test/ cannot import
// cmd/, AGENTS.md); this test proves the enforcement input is trustworthy
// end to end. Scope registry deliberately UNWIRED — no dependency on the
// sibling scope-matrix direction.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	saAudience      = "stripe-adapter" // the adapter's ExpectedAud / minted resource
	saClientE2E     = "checkout-e2e"
	saClientOther   = "checkout-other"
	saConsoleE2E    = "console-e2e"
	saConsoleLegacy = "console-legacy"
	saSecret        = "sa-secret"
	saIssuer        = "https://sso-stripe.test"
	saScope         = "billing:checkout:create"
	saUser          = "console-user"
)

// newStripeAdapterHarness builds an in-process AS with two tenant-bound
// machine clients (the A11-A13 shape), a tenant-bound console client
// (console-e2e), and a tenant-less legacy console client (console-legacy)
// — the A17/A18 user-token mint sources. Scope registry deliberately
// UNWIRED — no dependency on the sibling scope-matrix direction. Mirrors
// newScopeRegistryHarness (test/scope_registry_test.go) minus the scope
// registry; the user provider, password authenticator, and session manager
// are mandatory for /auth/login direct mints (createSessionRecord would
// nil-panic otherwise).
func newStripeAdapterHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: saUser})
	clients := defaultimpl.NewMemoryClientStore()
	for _, c := range []*sso.Client{
		{
			ID: saClientE2E, Secret: saSecret, Active: true,
			TenantID: "tenant-e2e", TokenStrategy: "jwt",
			AllowedScopes: []string{saScope, "admin:write"},
		},
		{
			ID: saClientOther, Secret: saSecret, Active: true,
			TenantID: "tenant-other", TokenStrategy: "jwt",
			AllowedScopes: []string{saScope, "admin:write"},
		},
		{
			ID: saConsoleE2E, Secret: saSecret, Active: true,
			TenantID: "tenant-e2e", TokenStrategy: "jwt",
			AllowedScopes:         []string{"admin:write"},
			AllowedAuthenticators: []string{"password"},
		},
		{
			ID: saConsoleLegacy, Secret: saSecret, Active: true,
			TenantID: "", TokenStrategy: "jwt",
			AllowedScopes:         []string{"admin:write"},
			AllowedAuthenticators: []string{"password"},
		},
	} {
		clients.AddSeed(c)
	}
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: saUser, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(saIssuer),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	srv := sso.NewServer(
		sso.WithIssuer(saIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// scCC mints a client_credentials token with the RFC 8707 resource field
// naming the adapter audience — required so the token carries aud, which
// rs.Config.ExpectedAud demands at the validation boundary.
func scCC(t *testing.T, srv *httptest.Server, clientID, resource string) (int, string, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {saSecret},
		"scope":         {saScope},
	}
	if resource != "" {
		form.Set("resource", resource)
	}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, string(raw), out
}

// TestStripeAdapterTenantClaim_MintAndProjection is A11+A12+A13: both
// client_credentials mints return 200, the wire payload carries the seeded
// tenant_id per client (never the request), aud is the compact single
// audience string (audClaim.MarshalJSON emits a scalar per OIDC), and the
// production rs middleware — configured exactly as the adapter mounts it —
// projects the claim into ClaimsFromContext.
func TestStripeAdapterTenantClaim_MintAndProjection(t *testing.T) {
	srv := newStripeAdapterHarness(t)

	for _, tc := range []struct {
		clientID, tenant string
	}{
		{clientID: saClientE2E, tenant: "tenant-e2e"},
		{clientID: saClientOther, tenant: "tenant-other"},
	} {
		status, raw, out := scCC(t, srv, tc.clientID, saAudience)
		if status != http.StatusOK {
			t.Fatalf("client %s: status=%d body=%s", tc.clientID, status, raw)
		}
		token, _ := out["access_token"].(string)
		if token == "" {
			t.Fatalf("client %s: no access_token in %v", tc.clientID, out)
		}
		// A11: wire claim tracks the client binding. The ok-guard makes a
		// missing claim fail loudly instead of silently skipping.
		payload := jwtAllClaims(t, token)
		got, ok := payload["tenant_id"].(string)
		if !ok || got != tc.tenant {
			t.Errorf("client %s: wire tenant_id = %v, want %q", tc.clientID, payload["tenant_id"], tc.tenant)
		}
		// Single audience is a compact string, never an array.
		if aud, ok := payload["aud"].(string); !ok || aud != saAudience {
			t.Errorf("client %s: aud = %v (%T), want the compact string %q", tc.clientID, payload["aud"], payload["aud"], saAudience)
		}

		// A12+A13: production rs middleware with the adapter's exact config
		// shape (JWT mode: Issuer + JWKSCache + ExpectedAud, no
		// IntrospectURL) projects TenantID into the downstream context.
		cache := rs.NewJWKSCache(srv.URL + core.PathJWKS)
		t.Cleanup(cache.Close)
		var gotTenant string
		var gotHas bool
		stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := rs.ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				t.Errorf("client %s: ClaimsFromContext missing", tc.clientID)
				return
			}
			gotTenant, gotHas = claims.TenantID, claims.HasTenantID()
			w.WriteHeader(http.StatusOK)
		})
		handler := rs.HTTPMiddleware(rs.Config{
			Issuer:      saIssuer,
			JWKSCache:   cache,
			ExpectedAud: saAudience,
		}, stub)
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("client %s: middleware status=%d, want 200", tc.clientID, rec.Code)
		}
		if gotTenant != tc.tenant || !gotHas {
			t.Errorf("client %s: ClaimsFromContext TenantID = %q, HasTenantID = %v, want %q/true",
				tc.clientID, gotTenant, gotHas, tc.tenant)
		}
	}
}

// saLogin drives the /auth/login direct mint (response_type=token) exactly
// as the console SPA would — the same proven surface as srLogin
// (test/scope_registry_test.go). Resource names the adapter audience so the
// token carries aud, which the adapter-shaped rs middleware demands.
func saLogin(t *testing.T, srv *httptest.Server, clientID string) (int, map[string]any) {
	t.Helper()
	return scPostJSON(t, srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     clientID,
		"response_type": "token",
		"credential":    map[string]string{"username": saUser, "password": "console-pass"},
		"scope":         []string{"admin:write"},
		"resource":      []string{saAudience},
	})
}

// projectClaims validates a bearer token through the PRODUCTION rs
// middleware the adapter mounts (JWT mode: Issuer + JWKSCache +
// ExpectedAud, no IntrospectURL — the exact adapter mount shape) and
// returns the projected claims.
func projectClaims(t *testing.T, srv *httptest.Server, token string) *rs.Claims {
	t.Helper()
	cache := rs.NewJWKSCache(srv.URL + core.PathJWKS)
	t.Cleanup(cache.Close)
	var got *rs.Claims
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := rs.ClaimsFromContext(r.Context())
		if !ok || claims == nil {
			t.Errorf("ClaimsFromContext missing")
			return
		}
		got = claims
		w.WriteHeader(http.StatusOK)
	})
	handler := rs.HTTPMiddleware(rs.Config{
		Issuer:      saIssuer,
		JWKSCache:   cache,
		ExpectedAud: saAudience,
	}, stub)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("middleware status=%d, want 200", rec.Code)
	}
	if got == nil {
		t.Fatal("middleware did not project claims")
	}
	return got
}

// TestStripeAdapterUserClaim_MintAndProjection is A17+A18 (T-9): the
// console user-flow mint sources behind the adapter's user gate. A console
// client seeded with a tenant binding (console-e2e) mints a wire tenant_id
// stamped from that binding and projects HasTenantID()==true through the
// production rs middleware — the exact shape the adapter's user gate
// accepts. A tenant-less console client (console-legacy) mints a 200
// claim-less token — no tenant_id key on the wire, HasTenantID()==false —
// the exact shape the unit gate rejects
// (TestCheckoutUserRejectsClaimlessToken). The gate decision itself stays
// unit-side (test/ cannot import cmd/); this test proves the enforcement
// input is trustworthy end to end.
func TestStripeAdapterUserClaim_MintAndProjection(t *testing.T) {
	srv := newStripeAdapterHarness(t)

	// A17: bound console client — binding-stamped tenant_id on the wire.
	status, out := saLogin(t, srv, saConsoleE2E)
	if status != http.StatusOK {
		t.Fatalf("console-e2e login: status=%d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("console-e2e: no access_token in %v", out)
	}
	payload := jwtAllClaims(t, token)
	if sub, _ := payload["sub"].(string); sub != saUser {
		t.Errorf("console-e2e: sub = %v, want %q", payload["sub"], saUser)
	}
	if clientID, _ := payload["client_id"].(string); clientID != saConsoleE2E {
		t.Errorf("console-e2e: client_id = %v, want %q", payload["client_id"], saConsoleE2E)
	}
	if payload["sub"] == payload["client_id"] {
		t.Errorf("console-e2e: sub must differ from client_id (user-shaped token)")
	}
	if scope, _ := payload["scope"].(string); scope != "admin:write" {
		t.Errorf("console-e2e: scope = %v, want the admin:write wire string", payload["scope"])
	}
	if tenant, ok := payload["tenant_id"].(string); !ok || tenant != "tenant-e2e" {
		t.Errorf("console-e2e: wire tenant_id = %v, want %q", payload["tenant_id"], "tenant-e2e")
	}
	if aud, ok := payload["aud"].(string); !ok || aud != saAudience {
		t.Errorf("console-e2e: aud = %v (%T), want the compact string %q", payload["aud"], payload["aud"], saAudience)
	}
	claims := projectClaims(t, srv, token)
	if claims.TenantID != "tenant-e2e" || !claims.HasTenantID() {
		t.Errorf("console-e2e: ClaimsFromContext TenantID = %q, HasTenantID = %v, want tenant-e2e/true",
			claims.TenantID, claims.HasTenantID())
	}

	// A18: legacy console client — 200 mint, claim-less wire shape.
	status, out = saLogin(t, srv, saConsoleLegacy)
	if status != http.StatusOK {
		t.Fatalf("console-legacy login: status=%d body=%v", status, out)
	}
	token, _ = out["access_token"].(string)
	if token == "" {
		t.Fatalf("console-legacy: no access_token in %v", out)
	}
	payload = jwtAllClaims(t, token)
	if _, present := payload["tenant_id"]; present {
		t.Errorf("console-legacy: wire carries tenant_id = %v, want no tenant_id key", payload["tenant_id"])
	}
	if sub, _ := payload["sub"].(string); sub != saUser {
		t.Errorf("console-legacy: sub = %v, want %q", payload["sub"], saUser)
	}
	claims = projectClaims(t, srv, token)
	if claims.HasTenantID() || claims.TenantID != "" {
		t.Errorf("console-legacy: ClaimsFromContext TenantID = %q, HasTenantID = %v, want empty/false",
			claims.TenantID, claims.HasTenantID())
	}
}

// TestStripeAdapterTenantClaim_ResourceRequired pins the RFC 8707
// precondition: without the resource field the token carries no aud, so the
// adapter-shaped middleware rejects on ErrAudienceMismatch — the e2e must
// mint with resource=stripe-adapter to prove anything about the tenant path.
func TestStripeAdapterTenantClaim_ResourceRequired(t *testing.T) {
	srv := newStripeAdapterHarness(t)
	status, raw, out := scCC(t, srv, saClientE2E, "")
	if status != http.StatusOK {
		t.Fatalf("mint without resource: status=%d body=%s", status, raw)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no access_token: %v", out)
	}
	if _, present := jwtAllClaims(t, token)["aud"]; present {
		t.Fatal("token minted without resource carries an aud claim")
	}

	cache := rs.NewJWKSCache(srv.URL + core.PathJWKS)
	t.Cleanup(cache.Close)
	handler := rs.HTTPMiddleware(rs.Config{
		Issuer:      saIssuer,
		JWKSCache:   cache,
		ExpectedAud: saAudience,
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("middleware status=%d, want 401 (audience mismatch)", rec.Code)
	}
}
