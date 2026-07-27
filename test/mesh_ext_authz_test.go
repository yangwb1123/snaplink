package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	meshUser     = "u-mesh"
	meshClient   = "mesh-client"
	meshSecret   = "mesh-secret"
	meshPassword = "pw"
)

// newMeshExtAuthzServer wires a *sso.Server with WithMeshExtAuthz so the
// HTTP-mode ext_authz endpoint is mounted at the default path. Returns the
// httptest server + a login helper that mints a real access token via the
// vetted /auth/login path (so the token under test is exactly what a mesh
// client would present).
func newMeshExtAuthzServer(t *testing.T, opts ...sso.Option) (*httptest.Server, func(scopes []string) string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: meshUser, Email: "mesh@example.com"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: meshClient, Secret: meshSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != meshPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: meshUser, Provider: "password"}, nil
		},
	))
	base := []sso.Option{
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(
			defaultimpl.WithEd25519Issuer("https://sso.test"),
			defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	srv := sso.NewServer(append(base, opts...)...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	login := func(scopes []string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  meshClient,
			"credential": map[string]string{"username": meshUser, "password": meshPassword},
			"scope":      scopes,
		})
		resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("no access_token: %v", out)
		}
		return tok
	}
	return httpSrv, login
}

func callMeshExtAuthz(t *testing.T, srv *httptest.Server, bearer string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+sso.PathMeshExtAuthz, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET ext_authz: %v", err)
	}
	return resp
}

// TestMeshExtAuthz_ValidBearer_AllowsWithIdentityHeaders proves the happy
// path: a valid bearer → 200 + DERIVED X-Auth-* identity headers + empty
// body + no-store. These are the headers Envoy injects upstream.
func TestMeshExtAuthz_ValidBearer_AllowsWithIdentityHeaders(t *testing.T) {
	srv, login := newMeshExtAuthzServer(t, sso.WithMeshExtAuthz(""))
	bearer := login([]string{"openid", "profile"})

	resp := callMeshExtAuthz(t, srv, bearer)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d want 200, body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get(sso.HeaderAuthSubject); got != meshUser {
		t.Errorf("X-Auth-Subject = %q want %q", got, meshUser)
	}
	if got := resp.Header.Get(sso.HeaderAuthClientID); got != meshClient {
		t.Errorf("X-Auth-Client-Id = %q want %q", got, meshClient)
	}
	scopes := resp.Header.Get(sso.HeaderAuthScopes)
	if !strings.Contains(scopes, "openid") || !strings.Contains(scopes, "profile") {
		t.Errorf("X-Auth-Scopes = %q want to contain openid + profile", scopes)
	}
	if got := resp.Header.Get(sso.HeaderAuthExpires); got == "" {
		t.Errorf("X-Auth-Expires missing")
	}
	// Empty body — Envoy reads status + headers only.
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("body = %q want empty", body)
	}
	// Credential-validating endpoint: must be no-store.
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q want no-store", cc)
	}
}

// TestMeshExtAuthz_MissingToken_DeniesWithBareChallenge: no token → 401 +
// a bare Bearer challenge (no error= per RFC 6750 §3.1).
func TestMeshExtAuthz_MissingToken_DeniesWithBareChallenge(t *testing.T) {
	srv, _ := newMeshExtAuthzServer(t, sso.WithMeshExtAuthz(""))

	resp := callMeshExtAuthz(t, srv, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(wa, "Bearer ") {
		t.Errorf("WWW-Authenticate = %q want Bearer challenge", wa)
	}
	if strings.Contains(wa, "error=") {
		t.Errorf("WWW-Authenticate = %q should omit error= for the no-credentials case", wa)
	}
	// No identity headers leak on a deny.
	if resp.Header.Get(sso.HeaderAuthSubject) != "" {
		t.Errorf("X-Auth-Subject leaked on deny")
	}
}

// TestMeshExtAuthz_InvalidToken_DeniesInvalidToken: garbage / invalid
// token → 401 + error="invalid_token" (same opaque failure as /userinfo).
func TestMeshExtAuthz_InvalidToken_DeniesInvalidToken(t *testing.T) {
	srv, _ := newMeshExtAuthzServer(t, sso.WithMeshExtAuthz(""))

	for _, tok := range []string{"garbage", "a.b.c", "not-a-jwt-at-all"} {
		resp := callMeshExtAuthz(t, srv, tok)
		if resp.StatusCode != http.StatusUnauthorized {
			_ = resp.Body.Close()
			t.Fatalf("token %q: status = %d want 401", tok, resp.StatusCode)
		}
		wa := resp.Header.Get("WWW-Authenticate")
		if !strings.Contains(wa, `error="invalid_token"`) {
			t.Errorf("token %q: WWW-Authenticate = %q want error=\"invalid_token\"", tok, wa)
		}
		_ = resp.Body.Close()
	}
}

// TestMeshExtAuthz_ExpiredToken_DeniesInvalidToken: an expired bearer is
// indistinguishable from any other invalid bearer on the wire.
func TestMeshExtAuthz_ExpiredToken_DeniesInvalidToken(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: meshUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: meshClient, Secret: meshSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: meshUser, Provider: "password"}, nil
		},
	))
	// 1ns TTL — the token is expired by the time ext_authz validates it.
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(
			defaultimpl.WithEd25519Issuer("https://sso.test"),
			defaultimpl.WithEd25519TokenTTL(time.Nanosecond))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithMeshExtAuthz(""),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  meshClient,
		"credential": map[string]string{"username": meshUser, "password": meshPassword},
	})
	lresp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(lresp.Body).Decode(&out)
	_ = lresp.Body.Close()
	bearer, _ := out["access_token"].(string)
	time.Sleep(5 * time.Millisecond)

	resp := callMeshExtAuthz(t, httpSrv, bearer)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401 (expired)", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q want invalid_token", resp.Header.Get("WWW-Authenticate"))
	}
}

// TestMeshExtAuthz_DPoPBoundTokenAsPlainBearer_Denies proves the sender-
// constraint is enforced: a DPoP-bound access token (cnf.jkt) presented
// WITHOUT a matching DPoP proof — i.e. as a plain bearer, the stolen-token
// replay scenario — is denied, mirroring /userinfo exactly.
func TestMeshExtAuthz_DPoPBoundTokenAsPlainBearer_Denies(t *testing.T) {
	srv, _ := newMeshExtAuthzServer(t, sso.WithMeshExtAuthz(""))

	// Mint a DPoP-bound token via client_credentials + a DPoP proof.
	priv, x := dpopGenKey(t)
	tokForm := "grant_type=client_credentials&client_id=" + meshClient +
		"&client_secret=" + meshSecret + "&scope=openid"
	tokReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(tokForm))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.Header.Set("DPoP", signDPoPProof(t, priv, x, "POST", srv.URL+"/token"))
	tokResp, err := http.DefaultClient.Do(tokReq)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	tokRB, _ := io.ReadAll(tokResp.Body)
	_ = tokResp.Body.Close()
	var tokOut map[string]any
	_ = json.Unmarshal(tokRB, &tokOut)
	if tokOut["token_type"] != "DPoP" {
		t.Fatalf("expected DPoP-bound token, got %v", tokOut)
	}
	access, _ := tokOut["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %s", tokRB)
	}

	// Present the bound token to ext_authz WITHOUT a DPoP proof → DENY.
	// A stolen sender-constrained token must not pass as a plain bearer.
	resp := callMeshExtAuthz(t, srv, access)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d want 401 (DPoP-bound token replayed as plain bearer) body=%s", resp.StatusCode, b)
	}
	if resp.Header.Get(sso.HeaderAuthSubject) != "" {
		t.Errorf("X-Auth-Subject leaked when sender-constraint failed")
	}
}

// TestMeshExtAuthz_OptInOff_RouteNotMounted proves the opt-in default:
// without WithMeshExtAuthz the path is 404 — byte-identical to a build
// without the feature.
func TestMeshExtAuthz_OptInOff_RouteNotMounted(t *testing.T) {
	srv, login := newMeshExtAuthzServer(t) // no WithMeshExtAuthz
	bearer := login([]string{"openid"})

	// Even a valid bearer must 404 — the route simply isn't registered.
	resp := callMeshExtAuthz(t, srv, bearer)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d want 404 (route not mounted when opt-in off)", resp.StatusCode)
	}
}
