package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// This file exercises the admin-gateway routing fix through the FULL
// composed handler — buildApp + buildHTTPHandler, exactly as cmd/sso-server's
// run() assembles it — with a real admin bearer validated by the real
// wired token issuer and a real permissions.Provider admin-scope check.
// admin_gateway_routing_test.go covers the routing TABLE in isolation; this
// file proves the real composition (real gRPC-gateway registrations, real
// AdminMiddleware, real SSO router handlers) behaves the same way end to
// end — closing the exact gap the bulk-revoke bug (commit fdebea60) exposed:
// unit tests that call a handler directly, or build *sso.Server alone,
// never exercise cmd/sso-server's outer mux and so never catch a routing
// regression here.

// adminGatewayE2EConfig extends fullFeatureConfig (cmd/sso-server's kitchen-
// sink config, already admin+permissions+tenants+snapshots+releases-enabled)
// with the additional wiring this suite's route sample needs:
//   - a dedicated test principal granted admin:* so mintAdminBearer's token
//     passes AdminMiddleware's scope gate (client_id "" mirrors the pattern
//     test/admin_middleware_test.go's adminProvider() uses)
//   - the token-usage recorder (token_anomaly.enabled), backing the SSO-
//     router-owned tokens/portfolio + tokens/usage surfaces
//   - the tenant usage aggregator, backing the SSO-router-owned
//     tenants/:id/usage surface
//   - the temp-token store, so the gateway's tokens/temp (IssueTempToken)
//     route has a non-nil TempStore to operate on
//
// Built fresh per call (fullFeatureConfig itself is fresh per call), so
// mutating it here cannot leak into any other test that also calls
// fullFeatureConfig.
func adminGatewayE2EConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := fullFeatureConfig(t)

	cfg.Permissions.Apps = append(cfg.Permissions.Apps, config.AppPermissionsConfig{
		ClientID: "",
		Roles:    []permissions.Role{{Code: "route-test-root", Permissions: []string{"admin:*"}}},
	})
	cfg.Permissions.UserRoles = append(cfg.Permissions.UserRoles, config.UserRoleAssignment{
		UserID: "route-test-admin", ClientID: "", Roles: []string{"route-test-root"},
	})

	// fullFeatureConfig never sets Server.TokenTTL (it never exercises a real
	// mint-then-validate round trip itself); serverbuildsign.BuildSigningIssuer
	// passes it to the issuer UNCONDITIONALLY (WithEd25519TokenTTL(srv.TokenTTL)),
	// which overrides the issuer's own sane package default with Go's zero
	// value — every token minted against that config expires the instant it's
	// issued ("ed25519: token expired" on the very next Validate call, found by
	// running this suite before adding this line). Must be set explicitly here.
	cfg.Server.TokenTTL = 15 * time.Minute

	cfg.TokenAnomaly.Enabled = true
	cfg.TokenAnomaly.SweepInterval = time.Hour

	cfg.Tenant.UsageMetering = config.TenantUsageMeteringConfig{Backend: "memory"}

	cfg.Authenticators.TempToken = &config.TempTokenConfig{Enabled: true, TTL: time.Hour}

	return cfg
}

// mintAdminBearer mints a real JWT access token via the same issuer instance
// the built app's AdminMiddleware validates against (a.server.ValidateToken
// tries every registered issuer) — the fastest route to a bearer the real
// admin gate accepts, without a live /auth/login + password/MFA round trip.
// Subject.Resources is left empty so the minted token's `aud` claim (which
// AdminMiddleware reads as the admin scope's client_id) is empty too,
// matching the client_id "" the permissions seed above grants admin:* under.
func mintAdminBearer(t *testing.T, a *app) string {
	t.Helper()
	iss, ok := a.tokenIssuers[sso.TokenStrategyJWT]
	if !ok {
		t.Fatal("jwt token issuer not wired")
	}
	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "route-test-admin"}, nil)
	if err != nil {
		t.Fatalf("mint admin bearer: %v", err)
	}
	return tok.AccessToken
}

// buildAdminGatewayE2EServer builds the full cmd/sso-server composition
// (buildApp + buildHTTPHandler), mints an admin bearer against it, and wraps
// it in a live httptest.Server. Cleanup (shutdownApp + server Close) is
// registered via t.Cleanup so every caller gets the same teardown
// TestBuildApp_FullFeatureSet uses.
func buildAdminGatewayE2EServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	cfg := adminGatewayE2EConfig(t)
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	// Keep the literal id used by this route inside ListExpiring's default
	// 30-day window. The exact gateway-path ownership is pinned separately;
	// this makes the full-composition request a stable non-404/200 signal.
	if err := a.clientStore.Add(context.Background(), &sso.Client{
		ID: "expiring", Secret: "route-test-secret", Active: true,
		SecretExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed expiring client: %v", err)
	}
	t.Cleanup(func() { shutdownApp(t, a) })
	h, err := buildHTTPHandler(cfg, a, quietLogger())
	if err != nil {
		t.Fatalf("buildHTTPHandler: %v", err)
	}
	bearer := mintAdminBearer(t, a)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, bearer
}

// adminAuthedRequest issues a bearer-authenticated request against the
// composed handler and returns (status, body).
func adminAuthedRequest(t *testing.T, srv *httptest.Server, method, path, bearer, body, contentType string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestAdminGatewayE2E_GatewayFamiliesReachRealGateway is the "did the fix
// break anything that used to work" regression check: at least one route
// per gateway resource family — clients, domains, keys, permissions,
// releases, snapshots, tenants, tokens/sessions, tokens/revoke, tokens/temp,
// users — must still reach the real grpc-gateway (never a 404) with a valid
// admin bearer through the FULL cmd/sso-server composition.
func TestAdminGatewayE2E_GatewayFamiliesReachRealGateway(t *testing.T) {
	t.Parallel()
	srv, bearer := buildAdminGatewayE2EServer(t)

	getCases := []string{
		"/api/v1/admin/clients",                            // clients
		"/api/v1/admin/clients/expiring",                   // clients ListExpiring
		"/api/v1/admin/domains",                            // domains
		"/api/v1/admin/keys",                               // keys
		"/api/v1/admin/permissions/web-app/roles",          // permissions
		"/api/v1/admin/permissions/web-app/sod/conflicts",  // SSoD
		"/api/v1/admin/permissions/web-app/dsod/conflicts", // DSoD
		"/api/v1/admin/releases",                           // releases
		"/api/v1/admin/snapshots",                          // snapshots
		"/api/v1/admin/tenants",                            // tenants
		"/api/v1/admin/tokens/sessions",                    // tokens/sessions
		"/api/v1/admin/users",                              // users (gateway's federated/external-identity shape)
	}
	for _, p := range getCases {
		// A clean 200 (verified empirically — every case in this list
		// returns one with this suite's wiring) is stronger proof than
		// merely "not 404": it confirms the request reached the gateway's
		// OWN List/Get handler, not just some other non-404 error path.
		code, body := adminAuthedRequest(t, srv, http.MethodGet, p, bearer, "", "")
		if code != http.StatusOK {
			t.Errorf("GET %s: status=%d, want 200 (gateway route not reached correctly); body=%s", p, code, body)
		}
	}

	// POST-only gateway routes: an empty JSON body is enough to prove the
	// request reached the gateway's OWN request binding/validation (a 4xx
	// from grpc-gateway) rather than the blanket routing-error 404 the whole
	// /api/v1/admin/ subtree used to produce before this fix.
	for _, p := range []string{"/api/v1/admin/tokens/revoke", "/api/v1/admin/tokens/temp"} {
		code, body := adminAuthedRequest(t, srv, http.MethodPost, p, bearer, "{}", "application/json")
		if code == http.StatusNotFound {
			t.Errorf("POST %s: status=404 (gateway route not reached); body=%s", p, body)
		}
	}
	for _, p := range []string{
		"/api/v1/admin/permissions/web-app/sod/conflicts",
		"/api/v1/admin/permissions/web-app/dsod/conflicts",
	} {
		code, body := adminAuthedRequest(t, srv, http.MethodPut, p, bearer, `{"conflict_sets":[]}`, "application/json")
		if code == http.StatusNotFound {
			t.Errorf("PUT %s: status=404 (gateway route not reached); body=%s", p, body)
		}
	}
}

// TestAdminGatewayE2E_SSORouterOnlyPathsReachRealRouter is the direct
// regression check for the bug this task fixes: every path here is
// SSO-router-owned and, before this fix, was UNCONDITIONALLY 404'd by the
// gateway's blanket routing-error handler whenever admin.api_rest_enabled
// (the reference binary's default). A non-404 here proves the request
// reached the SSO router's OWN handler logic.
//
// GET /api/v1/admin/tokens (the admin BEARER TOKEN lifecycle list,
// PathAdminTokens) is deliberately NOT included: cmd/sso-server never calls
// sso.WithAdminTokenStore (grep confirms no call site in this module), so
// that specific route is unmounted on the SSO router regardless of this
// fix — it would still 404 after the fix, for an unrelated pre-existing
// reason (no AdminTokenStore wiring path exists in the reference binary
// today). /api/v1/admin/tokens/usage is used instead as the representative
// "tokens family, SSO-router-owned" sample, since it IS reachable given this
// suite's config.
func TestAdminGatewayE2E_SSORouterOnlyPathsReachRealRouter(t *testing.T) {
	t.Parallel()
	srv, bearer := buildAdminGatewayE2EServer(t)

	cases := []string{
		sso.PathAPIPrefix + sso.PathAdminSessions,                              // GET /api/v1/admin/sessions
		sso.PathAPIPrefix + sso.PathAdminTokenPortfolio,                        // GET /api/v1/admin/tokens/portfolio
		sso.PathAPIPrefix + sso.PathAdminTokenUsage,                            // GET /api/v1/admin/tokens/usage
		strings.Replace(sso.PathAPIPrefix+sso.PathTenantUsage, ":id", "t1", 1), // GET /api/v1/admin/tenants/t1/usage
		sso.PathAPIPrefix + sso.PathAuditEvents,                                // GET /api/v1/audit/events — sanity: a different prefix, never affected by this bug either way, kept for full-composition coverage
	}
	for _, p := range cases {
		// A clean 200 (verified empirically for every case in this list with
		// this suite's wiring) is stronger proof than merely "not 404".
		code, body := adminAuthedRequest(t, srv, http.MethodGet, p, bearer, "", "")
		if code != http.StatusOK {
			t.Errorf("GET %s: status=%d, want 200 (still swallowed by the gateway's blanket routing error, or another regression); body=%s", p, code, body)
		}
	}
}

// TestAdminGatewayE2E_RemovedCarveOutsStillReachable proves the two ad-hoc
// exact-path carve-outs REMOVED from buildAdminRESTMux (the authz
// policy-bundle export and the wasmauthz debug check) are still reachable
// through the new adminGatewayExactPaths + "/" catch-all scheme, without
// needing their own special-case anymore.
func TestAdminGatewayE2E_RemovedCarveOutsStillReachable(t *testing.T) {
	t.Parallel()
	srv, bearer := buildAdminGatewayE2EServer(t)

	// The authz policy-bundle handler 400s on a missing client_id BEFORE
	// touching the client store — an unambiguous, ID-independent proof the
	// request reached interfaces/sso's OWN handler (a blanket gateway 404
	// would never produce this specific 400 body/behavior).
	code, body := adminAuthedRequest(t, srv, http.MethodGet, sso.PathAuthzPolicyBundle, bearer, "", "")
	if code == http.StatusNotFound {
		t.Fatalf("GET %s: status=404 (carve-out removal broke reachability); body=%s", sso.PathAuthzPolicyBundle, body)
	}
	if code != http.StatusBadRequest {
		t.Errorf("GET %s (no client_id): status=%d, want 400 missing_client_id; body=%s", sso.PathAuthzPolicyBundle, code, body)
	}

	// wasmauthz/check is never wired by cmd/sso-server (no config field
	// reaches sso.WithWASMAuthzEngine — grep confirms no call site in this
	// module), so it 404s from the SSO router's OWN "route not registered"
	// path both before and after this change. The meaningful assertion here
	// is that it's gated (401 without a bearer would also prove this, but
	// with a valid bearer a plain 404 from base is the expected — and
	// correct — outcome for an unmounted route); this is NOT the gateway's
	// blanket-subtree 404, since the outer mux no longer claims this path
	// for the gateway at all — the SSO router now owns the decision.
	code, body = adminAuthedRequest(t, srv, http.MethodGet, sso.PathAPIPrefix+sso.PathAdminWASMAuthzCheck, bearer, "", "")
	if code != http.StatusNotFound {
		t.Errorf("GET %s: status=%d, want 404 (unmounted — no WASMAuthzEngine wired in this test config); body=%s",
			sso.PathAPIPrefix+sso.PathAdminWASMAuthzCheck, code, body)
	}
}

// TestAdminGatewayE2E_BulkRevokeAndLocalUsersReachable exercises both fixes
// this task made (the pre-existing bulk-revoke fix, commit fdebea60, and the
// local-users rename added alongside this change) through the FULL
// cmd/sso-server composition — closing the exact gap noted in the task:
// test/admin_token_revoke_test.go's TestAdminBulkTokenRevoke_ReachableAtItsOwnPath
// only proves the SDK-level *sso.Server router serves these paths; it never
// exercises cmd/sso-server's outer mux, so it could not have caught (and
// would not catch a regression of) the gateway-shadowing bug itself.
func TestAdminGatewayE2E_BulkRevokeAndLocalUsersReachable(t *testing.T) {
	t.Parallel()
	srv, bearer := buildAdminGatewayE2EServer(t)

	// Bulk-revoke: a subject with no outstanding refresh tokens still
	// returns 200 with revoked_count=0 — the point is reachability, not the
	// count.
	form := url.Values{"subject": {"e2e-bulk-revoke-nobody"}, "confirm": {"true"}}
	code, body := adminAuthedRequest(t, srv, http.MethodPost, "/api/v1/admin/tokens/bulk-revoke", bearer,
		form.Encode(), "application/x-www-form-urlencoded")
	if code != http.StatusOK {
		t.Fatalf("POST /api/v1/admin/tokens/bulk-revoke: status=%d, want 200; body=%s", code, body)
	}

	// Local-users: create, then read back through the SAME (non-gateway)
	// path — proving this is genuinely the SSO router's local-user CRUD,
	// not an accidental hit on the gateway's federated-user List/Get.
	createBody := `{"username":"e2e-local-admin","email":"e2e-local-admin@example.com","password":"correcthorse1"}`
	code, body = adminAuthedRequest(t, srv, http.MethodPost, "/api/v1/admin/local-users", bearer, createBody, "application/json")
	if code != http.StatusCreated {
		t.Fatalf("POST /api/v1/admin/local-users: status=%d, want 201; body=%s", code, body)
	}
	if !strings.Contains(body, "e2e-local-admin") {
		t.Fatalf("POST /api/v1/admin/local-users: response missing created username; body=%s", body)
	}

	code, body = adminAuthedRequest(t, srv, http.MethodGet, "/api/v1/admin/local-users", bearer, "", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/local-users: status=%d, want 200; body=%s", code, body)
	}
	if !strings.Contains(body, "e2e-local-admin") {
		t.Fatalf("GET /api/v1/admin/local-users: list missing the just-created user; body=%s", body)
	}

	// The gateway's OWN /api/v1/admin/users List must still work — proving
	// the two surfaces are independent stores, not a rename-in-place that
	// accidentally merged them.
	code, body = adminAuthedRequest(t, srv, http.MethodGet, "/api/v1/admin/users", bearer, "", "")
	if code == http.StatusNotFound {
		t.Fatalf("GET /api/v1/admin/users (gateway): status=404 — the local-users rename must not have shadowed the gateway's own users list; body=%s", body)
	}
}

// TestAdminGatewayE2E_UnauthenticatedRequestsStill401 is a sanity guard
// against the mux restructuring accidentally bypassing the admin gate: both
// a gateway-owned path and a representative sample of SSO-router-owned
// paths must still require a valid admin bearer.
func TestAdminGatewayE2E_UnauthenticatedRequestsStill401(t *testing.T) {
	t.Parallel()
	cfg := adminGatewayE2EConfig(t)
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	t.Cleanup(func() { shutdownApp(t, a) })
	h, err := buildHTTPHandler(cfg, a, quietLogger())
	if err != nil {
		t.Fatalf("buildHTTPHandler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	for _, p := range []string{
		"/api/v1/admin/clients",     // gateway-owned
		"/api/v1/admin/sessions",    // SSO-router-owned
		"/api/v1/admin/local-users", // SSO-router-owned (this task's fix)
		sso.PathAuthzPolicyBundle,   // SSO-router-owned, carve-out removed by this change
	} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s unauthenticated: status=%d, want 401 (admin gate must cover both gateway and SSO-router paths)", p, resp.StatusCode)
		}
	}
}
