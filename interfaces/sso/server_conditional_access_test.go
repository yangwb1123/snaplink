package sso_test

// Drives the zero-trust conditional-access (CAP) advisory entry point and the
// read-only admin governance view end-to-end: the advisory method through the
// wired engine, and GET /api/v1/admin/access-policies through the real
// AdminMiddleware (admin:read gate).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

func denyLowTrustPolicy() conditionalaccess.Policy {
	return conditionalaccess.Policy{
		Name: "deny-low-trust", Priority: 100, Enabled: true,
		Conditions: conditionalaccess.Conditions{RiskScore: "> 0.5"},
		Actions:    conditionalaccess.Actions{Deny: true},
	}
}

func TestConditionalAccess_AdvisoryUnwired(t *testing.T) {
	t.Parallel()
	// A server without WithConditionalAccess returns a permissive allow so
	// callers can invoke the advisory method unconditionally.
	srv := sso.NewServer()
	d := srv.EvaluateConditionalAccess(context.Background(), sso.AccessContext{})
	if d.Verdict != conditionalaccess.VerdictAllow {
		t.Fatalf("unwired verdict = %q, want allow", d.Verdict)
	}
}

func TestConditionalAccess_AdvisoryWired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(ctx, denyLowTrustPolicy()); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	srv := sso.NewServer(sso.WithConditionalAccess(store, conditionalaccess.Config{}))

	// Low trust (0.1 -> risk 0.9) trips the deny policy.
	deny := srv.EvaluateConditionalAccess(ctx, sso.AccessContext{TrustScore: 0.1, TrustScoreKnown: true, DevicePosture: conditionalaccess.PostureManaged})
	if deny.Verdict != conditionalaccess.VerdictDeny || deny.MatchedPolicy != "deny-low-trust" {
		t.Fatalf("verdict %q matched %q, want deny/deny-low-trust", deny.Verdict, deny.MatchedPolicy)
	}
	// High trust (0.95 -> risk 0.05) does not match: default allow.
	allow := srv.EvaluateConditionalAccess(ctx, sso.AccessContext{TrustScore: 0.95, TrustScoreKnown: true, DevicePosture: conditionalaccess.PostureManaged})
	if allow.Verdict != conditionalaccess.VerdictAllow {
		t.Fatalf("high-trust verdict = %q, want allow", allow.Verdict)
	}
}

// capAdminEnv is an admin-gated httptest server with a wired CAP store.
type capAdminEnv struct {
	url   string
	token string
}

func capNewAdminServer(t *testing.T) *capAdminEnv {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, Name: "Admin Client",
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
	})

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, "", []string{"root"})
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"root"})

	capStore := conditionalaccess.NewMemoryStore()
	_ = capStore.Put(ctx, denyLowTrustPolicy())

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcovPasswordAuthAccepting()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithConditionalAccess(capStore, conditionalaccess.Config{}),
	)

	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("admin login status=%d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no admin token: %v", out)
	}
	return &capAdminEnv{url: httpSrv.URL, token: token}
}

func TestConditionalAccess_AdminGate(t *testing.T) {
	t.Parallel()
	env := capNewAdminServer(t)
	path := env.url + "/api/v1/admin/access-policies"

	// No bearer => 401.
	if status, _ := rcovDo(t, http.MethodGet, path, "", nil); status != http.StatusUnauthorized {
		t.Errorf("no-bearer = %d, want 401", status)
	}
	// Garbage bearer => 401.
	if status, _ := rcovDo(t, http.MethodGet, path, "garbage", nil); status != http.StatusUnauthorized {
		t.Errorf("bad-bearer = %d, want 401", status)
	}
	// Valid admin bearer => 200 with the policy listed.
	status, out := rcovDo(t, http.MethodGet, path, env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("admin list = %d body=%v", status, out)
	}
	policies, _ := out["policies"].([]any)
	if len(policies) != 1 {
		t.Fatalf("policies = %d, want 1 (body=%v)", len(policies), out)
	}
	total, _ := out["total"].(float64)
	if int(total) != 1 {
		t.Errorf("total = %v, want 1", out["total"])
	}
}
