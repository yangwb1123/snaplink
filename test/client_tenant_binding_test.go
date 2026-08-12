package ssotest

// E-1..E-3: wire-level acceptance for surfacing the client's tenant binding
// on the admin wire. One real deployment (sso.Server + admin gRPC-gateway
// over the SAME MemoryClientStore) proves the surfaced admin value equals
// the minted token's tenant_id claim — the cross-reference the deploy sweep
// (`check --expect-tenant-id`) is built to close.
//
// T-C invariant (seed contract): every seeded client that the sweep mints
// against MUST include "client_credentials" in GrantTypes, or
// rejectDisallowedGrantType (interfaces/sso/server_token.go) returns
// 400 unauthorized_client before any claim is produced.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver/grpcadmin"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// newTenantBindingDeployment builds one real deployment: a live sso.Server
// whose issuer URL is the listener address (so the discovery doc, JWKS, and
// minted-token iss all agree), plus the admin gRPC-gateway (default
// protojson marshaler: camelCase, EmitUnpopulated) mounted on the exact
// /api/v1/admin/clients patterns behind the AdminMiddleware. Everything
// else falls through to the SSO router. Seeded clients:
//
//	client-1  bound tenant-acme, cc mintable (T-C)
//	client-2  bound tenant-other, cc mintable (T-C)
//	client-3  unbound (TenantID ""), cc mintable (T-C)
//
// All three carry non-empty AllowedScopes so the sweep's T-8d probe scope is
// never granted, and TokenStrategy jwt so minted tokens carry claims.
func newTenantBindingDeployment(t *testing.T) *httptest.Server {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := "http://" + lis.Addr().String()

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "client-1", Secret: "s", Active: true, TokenStrategy: "jwt",
		Name:          "Tenant Acme App",
		AllowedScopes: []string{"openid", "profile"},
		// T-C: client_credentials is mandatory for the sweep mint leg.
		GrantTypes: []string{"client_credentials", "authorization_code", "refresh_token"},
		TenantID:   "tenant-acme",
	})
	clients.AddSeed(&sso.Client{
		ID: "client-2", Secret: "s2", Active: true, TokenStrategy: "jwt",
		Name:          "Other Tenant App",
		AllowedScopes: []string{"openid"},
		// T-C: client_credentials is mandatory for the sweep mint leg.
		GrantTypes: []string{"client_credentials"},
		TenantID:   "tenant-other",
	})
	clients.AddSeed(&sso.Client{
		ID: "client-3", Secret: "s3", Active: true, TokenStrategy: "jwt",
		Name:          "Unbound App",
		AllowedScopes: []string{"openid"},
		// T-C: client_credentials is mandatory for the sweep mint leg.
		GrantTypes: []string{"client_credentials"},
		// TenantID intentionally empty: single-tenant byte-compat leg.
	})

	// Shared issuer for access tokens: WithEd25519Issuer(addr) makes the
	// minted iss equal the discovery issuer (the apiclient sweep asserts
	// this; omitting it makes every sweep fail on iss before tenant_id).
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(addr),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	srv := sso.NewServer(
		sso.WithIssuer(addr),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
	)

	gw := runtime.NewServeMux()
	if err := adminv1.RegisterClientAdminServiceHandlerServer(
		context.Background(), gw,
		grpcadmin.NewClientAdminService(clients, nil, nil, nil),
	); err != nil {
		t.Fatalf("register admin gateway: %v", err)
	}
	mw := sso.NewAdminMiddleware(
		stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-alice"}},
		adminProvider(t),
	)
	gated := mw.HTTPMiddleware(gw)

	outer := http.NewServeMux()
	outer.Handle("/api/v1/admin/clients", gated)
	outer.Handle("/api/v1/admin/clients/", gated)
	outer.Handle("/", srv.Handler())

	httpSrv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: outer}}
	httpSrv.Start()
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// adminClientGet fetches one client over the admin wire with a valid admin
// bearer and decodes the gateway's camelCase JSON into a generic map.
func adminClientGet(t *testing.T, srv *httptest.Server, clientID string) map[string]any {
	t.Helper()
	resp := httpDo(t, "GET", srv.URL+"/api/v1/admin/clients/"+clientID, "good")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin GET %s: status %d, want 200", clientID, resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("admin GET %s: decode: %v", clientID, err)
	}
	clientObj, ok := body["client"].(map[string]any)
	if !ok {
		t.Fatalf("admin GET %s: response has no client object: %v", clientID, body)
	}
	return clientObj
}

// mintClientCredentials performs the client-credentials mint exactly like
// the sweep's mint leg (Basic credentials, form body) and returns the
// decoded JWT payload.
func mintClientCredentials(t *testing.T, srv *httptest.Server, clientID, secret string) map[string]any {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}}
	req, _ := http.NewRequest("POST", srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("mint %s: %v", clientID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mint %s: status %d, want 200", clientID, resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("mint %s: decode: %v", clientID, err)
	}
	if out.AccessToken == "" {
		t.Fatalf("mint %s: empty access_token", clientID)
	}
	return decodeJWTPayload(t, out.AccessToken)
}

// TestClientTenantBinding_AdminWireEqualsTokenClaim is E-1: the admin wire's
// tenantId for a bound client equals the tenant_id claim of the token that
// client can mint — the exact cross-reference `check --expect-tenant-id`
// makes at deploy time.
func TestClientTenantBinding_AdminWireEqualsTokenClaim(t *testing.T) {
	srv := newTenantBindingDeployment(t)

	clientObj := adminClientGet(t, srv, "client-1")
	wireTenant, _ := clientObj["tenantId"].(string)
	if wireTenant != "tenant-acme" {
		t.Fatalf("admin wire tenantId = %q, want %q", wireTenant, "tenant-acme")
	}

	payload := mintClientCredentials(t, srv, "client-1", "s")
	claimTenant, _ := payload["tenant_id"].(string)
	if claimTenant != "tenant-acme" {
		t.Fatalf("token tenant_id claim = %q, want %q", claimTenant, "tenant-acme")
	}
	if wireTenant != claimTenant {
		t.Fatalf("admin wire tenantId %q != token tenant_id claim %q", wireTenant, claimTenant)
	}

	// GrantTypes surface too, matching the seed allowlist.
	grants, _ := clientObj["grantTypes"].([]any)
	if len(grants) != 3 {
		t.Fatalf("admin wire grantTypes = %v, want 3 entries", clientObj["grantTypes"])
	}
}

// TestClientTenantBinding_MisBoundClientVisiblePreRuntime is E-2: a second
// tenant's binding shows identically on the admin wire and in the minted
// claim, so a declaration mismatch (a sweep expecting tenant-acme against
// this client) fails consistently on both surfaces — the named harm is
// visible before any runtime decision.
func TestClientTenantBinding_MisBoundClientVisiblePreRuntime(t *testing.T) {
	srv := newTenantBindingDeployment(t)

	clientObj := adminClientGet(t, srv, "client-2")
	wireTenant, _ := clientObj["tenantId"].(string)
	if wireTenant != "tenant-other" {
		t.Fatalf("admin wire tenantId = %q, want %q", wireTenant, "tenant-other")
	}

	payload := mintClientCredentials(t, srv, "client-2", "s2")
	claimTenant, _ := payload["tenant_id"].(string)
	if claimTenant != "tenant-other" {
		t.Fatalf("token tenant_id claim = %q, want %q", claimTenant, "tenant-other")
	}
	if claimTenant != wireTenant {
		t.Fatalf("wire %q != claim %q for the same client", wireTenant, claimTenant)
	}
}

// TestClientTenantBinding_UnboundClientBytesCompatible is E-3: an unbound
// client emits "tenantId":"" on the admin wire (EmitUnpopulated, additive
// key) while its minted token carries NO tenant_id claim (omitempty) —
// single-tenant deployments stay byte-compatible on the claim surface.
func TestClientTenantBinding_UnboundClientBytesCompatible(t *testing.T) {
	srv := newTenantBindingDeployment(t)

	clientObj := adminClientGet(t, srv, "client-3")
	wireTenant, present := clientObj["tenantId"].(string)
	if !present || wireTenant != "" {
		t.Fatalf("unbound client tenantId = %q (present=%v), want \"\"", wireTenant, present)
	}

	payload := mintClientCredentials(t, srv, "client-3", "s3")
	if _, ok := payload["tenant_id"]; ok {
		t.Fatalf("unbound client token carries tenant_id claim %q, want absent", payload["tenant_id"])
	}
}
