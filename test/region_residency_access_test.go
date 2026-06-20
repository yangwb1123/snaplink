package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/region"
	tenantmemory "github.com/snaplink/sso/domains/tenant/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// These are the live integration tests for the READ-side of data residency:
// a token for a region-constrained tenant rejected when USED from a
// disallowed serving region on the resource-ACCESS bearer endpoints
// (/userinfo + mesh ext_authz). They are the access-side counterpart to the
// login WRITE-gate tests in region_residency_test.go. The token is always
// minted from the tenant's HOME region (so issuance succeeds), then presented
// from a varied serving region — proving the gate is on USE, not issuance.

const (
	residencyAccessUser      = "user-access"
	residencyAccessPass      = "pw"
	residencyConstrained     = "constrained-app" // bound to residencyTenantID (eu-west-1 only)
	residencyUnconstrained   = "unconstrained-app"
	residencyAccessSrvHeader = "X-Serving-Region"
)

// residencyAccessFixture wires a full server whose serving region is resolved
// from a request header (Default = the tenant's home eu-west-1). A JWT issuer
// is shared by access + id token so a minted access token validates as a
// bearer at /userinfo + mesh ext_authz. Two clients are seeded: one bound to
// the eu-west-1-only tenant, one with NO tenant (unconstrained). When
// wireRegion is false neither the region middleware nor the residency check is
// installed — the inert / byte-identical path.
func residencyAccessFixture(t *testing.T, wireRegion bool) (*httptest.Server, func(clientID string) string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{
		ID: residencyAccessUser, Email: "access@example.com", Name: "Access User",
	})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: residencyConstrained, Active: true,
		TenantID:              residencyTenantID, // eu-west-1 home, eu-west-1 only
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	clients.AddSeed(&sso.Client{
		ID: residencyUnconstrained, Active: true,
		// No TenantID — unbound, residency has nothing to gate on.
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != residencyAccessPass {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: residencyAccessUser, Provider: "password"}, nil
		},
	))

	tstore := tenantmemory.New()
	// EnforceWrites=true on the tenant, but reads use isWrite=false, so only
	// the AllowedRegions check (eu-west-1 only) can fire on the access side.
	if err := tstore.PutTenant(context.Background(), residencyTenant(true)); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.test"),
		defaultimpl.WithEd25519TokenTTL(2*time.Minute),
	)
	opts := []sso.Option{
		sso.WithIssuer("https://sso.test"),
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantStore(tstore),
		sso.WithMeshExtAuthz(""),
	}
	if wireRegion {
		// Home region is the header Default — a request without the header
		// resolves to eu-west-1 (allowed). With it, traffic pins to the named
		// region (us-east-1 → disallowed).
		opts = append(opts,
			sso.WithRegionMiddleware(region.HeaderResolver{
				Header:  residencyAccessSrvHeader,
				Default: "eu-west-1",
			}, region.MiddlewareOptions{}),
			sso.WithTenantResidencyCheck(0),
		)
	}
	srv := sso.NewServer(opts...)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// login mints a real access token from the HOME region (no serving header)
	// so issuance always succeeds — the access-side gate is what we exercise.
	login := func(clientID string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  clientID,
			"credential": map[string]string{"username": residencyAccessUser, "password": residencyAccessPass},
			"scope":      []string{"openid", "profile", "email"},
		})
		resp, err := http.Post(ts.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		rb, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("home login status=%d body=%s", resp.StatusCode, rb)
		}
		out := map[string]any{}
		_ = json.Unmarshal(rb, &out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("no access_token for %s: %v", clientID, out)
		}
		return tok
	}
	return ts, login
}

// getUserInfo calls /userinfo with the bearer, pinning the serving region via
// the header (empty servingRegion → no header → home region eu-west-1).
func getUserInfo(t *testing.T, ts *httptest.Server, bearer, servingRegion string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	if servingRegion != "" {
		req.Header.Set(residencyAccessSrvHeader, servingRegion)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	rb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	out := map[string]any{}
	if len(rb) > 0 {
		_ = json.Unmarshal(rb, &out)
	}
	return resp, out
}

// getMeshExtAuthz calls the mesh ext_authz endpoint with the bearer, pinning
// the serving region via the header.
func getMeshExtAuthz(t *testing.T, ts *httptest.Server, bearer, servingRegion string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+sso.PathMeshExtAuthz, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	if servingRegion != "" {
		req.Header.Set(residencyAccessSrvHeader, servingRegion)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", sso.PathMeshExtAuthz, err)
	}
	return resp
}

// TestResidencyAccess_Userinfo_DisallowedRegion_403 proves the core read-side
// control: a VALID token for the eu-west-1-only tenant, presented to /userinfo
// from us-east-1, is rejected with a 403 carrying region_not_allowed — NOT a
// 401 invalid_token (the token IS valid; this is a policy denial). The 403
// must still carry no-store headers (the endpoint stamps them at entry).
func TestResidencyAccess_Userinfo_DisallowedRegion_403(t *testing.T) {
	ts, login := residencyAccessFixture(t, true)
	bearer := login(residencyConstrained)

	resp, body := getUserInfo(t, ts, bearer, "us-east-1")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%v)", resp.StatusCode, body)
	}
	if got := body[sso.KeyError]; got != sso.ErrRegionNotAllowed {
		t.Errorf("error = %v, want %q", got, sso.ErrRegionNotAllowed)
	}
	// A residency denial is NOT a bearer-challenge — the token is valid, so
	// there must be no WWW-Authenticate invalid_token on this 403.
	if ch := resp.Header.Get("WWW-Authenticate"); ch != "" {
		t.Errorf("residency 403 carried a WWW-Authenticate challenge %q (token IS valid)", ch)
	}
	// no-store must hold on the new 403 — a cached cross-user denial would be
	// just as bad as a cached 200.
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store on residency 403", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache on residency 403", got)
	}
}

// TestResidencyAccess_Userinfo_AllowedRegion_200 proves the same token served
// from the tenant's allowed home region returns the claims normally.
func TestResidencyAccess_Userinfo_AllowedRegion_200(t *testing.T) {
	ts, login := residencyAccessFixture(t, true)
	bearer := login(residencyConstrained)

	resp, body := getUserInfo(t, ts, bearer, "eu-west-1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%v)", resp.StatusCode, body)
	}
	if got, _ := body["sub"].(string); got != residencyAccessUser {
		t.Errorf("sub = %v, want %q", body["sub"], residencyAccessUser)
	}
}

// TestResidencyAccess_Userinfo_UnconstrainedTenant_200 proves a token for an
// UNCONSTRAINED tenant (the unbound client) is served from ANY region — the
// gate has no tenant binding to enforce.
func TestResidencyAccess_Userinfo_UnconstrainedTenant_200(t *testing.T) {
	ts, login := residencyAccessFixture(t, true)
	bearer := login(residencyUnconstrained)

	resp, body := getUserInfo(t, ts, bearer, "us-east-1") // disallowed for the OTHER tenant
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for unconstrained tenant (body=%v)", resp.StatusCode, body)
	}
	if got, _ := body["sub"].(string); got != residencyAccessUser {
		t.Errorf("sub = %v, want %q", body["sub"], residencyAccessUser)
	}
}

// TestResidencyAccess_Mesh_DisallowedRegion_Deny proves the mesh contract: a
// valid token for the constrained tenant from a disallowed region is DENIED
// (401, body-less, NO X-Auth-* headers) — oracle-safe, indistinguishable from
// an invalid-token DENY.
func TestResidencyAccess_Mesh_DisallowedRegion_Deny(t *testing.T) {
	ts, login := residencyAccessFixture(t, true)
	bearer := login(residencyConstrained)

	resp := getMeshExtAuthz(t, ts, bearer, "us-east-1")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		rb, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 401 DENY (body=%s)", resp.StatusCode, rb)
	}
	// DENY must not stamp identity — a residency-denied request is upstream-invisible.
	if got := resp.Header.Get(sso.HeaderAuthSubject); got != "" {
		t.Errorf("X-Auth-Subject stamped on a DENIED request: %q", got)
	}
	// Body-less, like any other mesh DENY (oracle-safe).
	rb, _ := io.ReadAll(resp.Body)
	if len(rb) != 0 {
		t.Errorf("mesh DENY carried a body: %q", rb)
	}
}

// TestResidencyAccess_Mesh_AllowedRegion_Allow proves the same token from the
// allowed region ALLOWs (200 + X-Auth-* identity headers).
func TestResidencyAccess_Mesh_AllowedRegion_Allow(t *testing.T) {
	ts, login := residencyAccessFixture(t, true)
	bearer := login(residencyConstrained)

	resp := getMeshExtAuthz(t, ts, bearer, "eu-west-1")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 ALLOW (body=%s)", resp.StatusCode, rb)
	}
	if got := resp.Header.Get(sso.HeaderAuthSubject); got != residencyAccessUser {
		t.Errorf("X-Auth-Subject = %q, want %q on ALLOW", got, residencyAccessUser)
	}
}

// TestResidencyAccess_NoRegionWired_ByteIdentical proves the nil-default
// guarantee at the wire level: the SAME constrained tenant + client, but with
// NO region middleware / residency check, serves /userinfo (200) and mesh
// ALLOW even though the home region would be the only "allowed" one — the
// gate never runs (FromHandlerContext reports no region), and crucially does
// NO tenant lookup. This is the zero-behavioral-change-when-disabled proof.
func TestResidencyAccess_NoRegionWired_ByteIdentical(t *testing.T) {
	ts, login := residencyAccessFixture(t, false)
	bearer := login(residencyConstrained)

	// /userinfo — served (no serving region resolved, gate skipped entirely).
	resp, body := getUserInfo(t, ts, bearer, "us-east-1") // header ignored, no middleware
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/userinfo status = %d, want 200 (inert residency) body=%v", resp.StatusCode, body)
	}
	if got, _ := body["sub"].(string); got != residencyAccessUser {
		t.Errorf("sub = %v, want %q", body["sub"], residencyAccessUser)
	}

	// mesh — ALLOW with identity headers.
	mr := getMeshExtAuthz(t, ts, bearer, "us-east-1")
	defer func() { _ = mr.Body.Close() }()
	if mr.StatusCode != http.StatusOK {
		t.Fatalf("mesh status = %d, want 200 ALLOW (inert residency)", mr.StatusCode)
	}
	if got := mr.Header.Get(sso.HeaderAuthSubject); got != residencyAccessUser {
		t.Errorf("X-Auth-Subject = %q, want %q on inert ALLOW", got, residencyAccessUser)
	}
}
