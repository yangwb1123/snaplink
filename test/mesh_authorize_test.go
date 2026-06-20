package ssotest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/domains/region"
	tenantmemory "github.com/snaplink/sso/domains/tenant/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// These tests exercise the dep-free s.MeshAuthorize seam (Phase A of gRPC
// ext_authz) DIRECTLY — the pure ALLOW/DENY decision + derived identity the
// HTTP handler and a future go-control-plane gRPC module both reuse. The
// HTTP byte-identical guarantee is locked separately by
// mesh_ext_authz_test.go (the handler tests stay green over this refactor);
// here we assert the decision contract itself: sender-constraint, oracle-safe
// deny, and identity-derivation equivalence with the HTTP handler.

// newMeshAuthorizeServer wires a *sso.Server and returns it directly (plus a
// login helper that mints a real access token via /auth/login) so tests can
// call srv.MeshAuthorize without going over HTTP. Mirrors
// newMeshExtAuthzServer but exposes the *sso.Server.
func newMeshAuthorizeServer(t *testing.T, opts ...sso.Option) (*sso.Server, *httptest.Server, func(scopes []string) string) {
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
	return srv, httpSrv, login
}

// bearerHeader builds an http.Header carrying just the bearer (the minimal
// MeshAuthorizeRequest header for a plain-bearer call).
func bearerHeader(tok string) http.Header {
	h := make(http.Header)
	if tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	return h
}

// TestMeshAuthorize_ValidBearer_AllowsWithDerivedIdentity: a valid bearer →
// Allowed + the derived Subject/ClientID/Scopes/ExpiresAt straight from the
// token (no permissions provider ⇒ no Roles).
func TestMeshAuthorize_ValidBearer_AllowsWithDerivedIdentity(t *testing.T) {
	srv, _, login := newMeshAuthorizeServer(t, sso.WithMeshExtAuthz(""))
	bearer := login([]string{"openid", "profile"})

	res := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    "https://sso.test" + sso.PathMeshExtAuthz,
		Header: bearerHeader(bearer),
	})
	if !res.Allowed {
		t.Fatalf("Allowed = false want true (deny=%q)", res.DenyCode)
	}
	if res.Subject != meshUser {
		t.Errorf("Subject = %q want %q", res.Subject, meshUser)
	}
	if res.ClientID != meshClient {
		t.Errorf("ClientID = %q want %q", res.ClientID, meshClient)
	}
	if !meshContains(res.Scopes, "openid") || !meshContains(res.Scopes, "profile") {
		t.Errorf("Scopes = %v want openid+profile", res.Scopes)
	}
	if res.ExpiresAt == 0 {
		t.Errorf("ExpiresAt = 0 want a future exp")
	}
	if res.DenyCode != "" {
		t.Errorf("DenyCode = %q want empty on ALLOW", res.DenyCode)
	}
	if len(res.Roles) != 0 {
		t.Errorf("Roles = %v want none (no permissions provider)", res.Roles)
	}
}

// TestMeshAuthorize_MissingToken_DeniesWithEmptyCode: no bearer → DENY with
// an empty DenyCode (the bare-challenge / missing-credentials case, distinct
// from an invalid token — the only distinction /userinfo exposes).
func TestMeshAuthorize_MissingToken_DeniesWithEmptyCode(t *testing.T) {
	srv, _, _ := newMeshAuthorizeServer(t, sso.WithMeshExtAuthz(""))
	res := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    "https://sso.test" + sso.PathMeshExtAuthz,
		Header: bearerHeader(""),
	})
	if res.Allowed {
		t.Fatalf("Allowed = true want false (missing token)")
	}
	if res.DenyCode != "" {
		t.Errorf("DenyCode = %q want empty (bare-challenge case)", res.DenyCode)
	}
	if res.Subject != "" || res.ClientID != "" || len(res.Scopes) != 0 {
		t.Errorf("identity leaked on deny: %+v", res)
	}
}

// TestMeshAuthorize_InvalidToken_DeniesInvalidToken: garbage tokens → DENY
// with the oracle-safe invalid_token code (no per-cause detail).
func TestMeshAuthorize_InvalidToken_DeniesInvalidToken(t *testing.T) {
	srv, _, _ := newMeshAuthorizeServer(t, sso.WithMeshExtAuthz(""))
	for _, tok := range []string{"garbage", "a.b.c", "not-a-jwt-at-all"} {
		res := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
			Method: http.MethodGet,
			URL:    "https://sso.test" + sso.PathMeshExtAuthz,
			Header: bearerHeader(tok),
		})
		if res.Allowed {
			t.Fatalf("token %q: Allowed = true want false", tok)
		}
		if res.DenyCode != sso.ErrInvalidToken {
			t.Errorf("token %q: DenyCode = %q want %q", tok, res.DenyCode, sso.ErrInvalidToken)
		}
		if res.Subject != "" {
			t.Errorf("token %q: Subject leaked on deny", tok)
		}
	}
}

// TestMeshAuthorize_ExpiredToken_DeniesInvalidToken: an expired bearer is
// indistinguishable from any other invalid bearer (invalid_token).
func TestMeshAuthorize_ExpiredToken_DeniesInvalidToken(t *testing.T) {
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

	res := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    "https://sso.test" + sso.PathMeshExtAuthz,
		Header: bearerHeader(bearer),
	})
	if res.Allowed {
		t.Fatalf("Allowed = true want false (expired)")
	}
	if res.DenyCode != sso.ErrInvalidToken {
		t.Errorf("DenyCode = %q want invalid_token", res.DenyCode)
	}
}

// TestMeshAuthorize_RolesDerivedWhenPermissionsWired: with a permissions
// provider wired AND a role assigned, ALLOW carries X-Auth-Roles-equivalent
// Roles derived from the provider.
func TestMeshAuthorize_RolesDerivedWhenPermissionsWired(t *testing.T) {
	perms := permissions.NewMemoryProvider()
	// Define + assign a role for the mesh user so the lookup is non-empty
	// (Roles() returns only assigned codes that are ALSO defined).
	if err := perms.AddRole(context.Background(), meshClient, permissions.Role{Code: "viewer", Permissions: []string{"read"}}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := perms.AssignRoles(context.Background(), meshUser, meshClient, []string{"viewer"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	srv, _, login := newMeshAuthorizeServer(t,
		sso.WithMeshExtAuthz(""),
		sso.WithPermissionProvider(perms),
	)
	bearer := login([]string{"openid"})

	res := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    "https://sso.test" + sso.PathMeshExtAuthz,
		Header: bearerHeader(bearer),
	})
	if !res.Allowed {
		t.Fatalf("Allowed = false want true (deny=%q)", res.DenyCode)
	}
	if !meshContains(res.Roles, "viewer") {
		t.Errorf("Roles = %v want to contain viewer", res.Roles)
	}
}

// TestMeshAuthorize_DPoPBoundTokenAsPlainBearer_Denies proves the sender-
// constraint through the seam: a DPoP-bound token (cnf.jkt) presented WITHOUT
// a DPoP proof — the stolen-token replay scenario — is DENIED (invalid_token),
// never ALLOWED as a plain bearer.
func TestMeshAuthorize_DPoPBoundTokenAsPlainBearer_Denies(t *testing.T) {
	srv, httpSrv, _ := newMeshAuthorizeServer(t, sso.WithMeshExtAuthz(""))
	access := mintDPoPBoundToken(t, httpSrv)

	res := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    "https://sso.test" + sso.PathMeshExtAuthz,
		Header: bearerHeader(access), // NO DPoP proof header
	})
	if res.Allowed {
		t.Fatalf("Allowed = true want false (DPoP-bound token replayed as plain bearer)")
	}
	if res.DenyCode != sso.ErrInvalidToken {
		t.Errorf("DenyCode = %q want invalid_token", res.DenyCode)
	}
	if res.Subject != "" {
		t.Errorf("Subject leaked when sender-constraint failed")
	}
}

// TestMeshAuthorize_DPoPProof_HtmHtuMismatch_Denies proves the DPoP htm/htu
// binding is enforced through the seam: a DPoP-bound token presented WITH a
// proof whose htm/htu don't match req.Method/URL is DENIED. (A correctly
// bound proof — htm/htu matching req — ALLOWS, the positive control.)
func TestMeshAuthorize_DPoPProof_HtmHtuMismatch_Denies(t *testing.T) {
	srv, httpSrv, _ := newMeshAuthorizeServer(t, sso.WithMeshExtAuthz(""))
	priv, x := dpopGenKey(t)
	access := mintDPoPBoundTokenWithKey(t, httpSrv, priv, x)

	// The htu a DPoP proof must match is what requestURLForDPoP rebuilds from
	// the request: scheme://host/path, with scheme/host taken from the
	// X-Forwarded-* chain (the TLS-terminating edge / mesh sets them). So the
	// request carries X-Forwarded-Proto/Host that resolve to this canonical
	// URL, and the proof is signed against it. (For the HTTP handler, the
	// same requestURLForDPoP runs on the real request — the proof a real DPoP
	// client signs is the public URL.)
	const meshURL = "https://sso.test" + sso.PathMeshExtAuthz
	fwd := func(tok string) http.Header {
		h := bearerHeader(tok)
		h.Set("X-Forwarded-Proto", "https")
		h.Set("X-Forwarded-Host", "sso.test")
		return h
	}

	// Mismatched proof: signed for POST https://evil.example/other, but the
	// request is GET meshURL → htm + htu mismatch → DENY.
	hBad := fwd(access)
	hBad.Set("DPoP", signDPoPProof(t, priv, x, http.MethodPost, "https://evil.example/other"))
	resBad := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    meshURL,
		Header: hBad,
	})
	if resBad.Allowed {
		t.Fatalf("Allowed = true want false (DPoP htm/htu mismatch)")
	}
	if resBad.DenyCode != sso.ErrInvalidToken {
		t.Errorf("DenyCode = %q want invalid_token", resBad.DenyCode)
	}

	// Positive control: a proof correctly bound to GET meshURL → ALLOW, with
	// the same derived subject. Proves the deny above is the binding, not an
	// unrelated rejection.
	hGood := fwd(access)
	hGood.Set("DPoP", signDPoPProof(t, priv, x, http.MethodGet, meshURL))
	resGood := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    meshURL,
		Header: hGood,
	})
	if !resGood.Allowed {
		t.Fatalf("Allowed = false want true (correctly bound DPoP proof) deny=%q", resGood.DenyCode)
	}
	// client_credentials sub == client_id (RFC 6749 §4.4) — the token was
	// minted via client_credentials, not a user login.
	if resGood.Subject != meshClient {
		t.Errorf("Subject = %q want %q (client_credentials sub)", resGood.Subject, meshClient)
	}
	if resGood.ClientID != meshClient {
		t.Errorf("ClientID = %q want %q", resGood.ClientID, meshClient)
	}
}

// TestMeshAuthorize_IdentityMatchesHTTPHandler proves the seam and the HTTP
// handler emit the SAME derived identity for the same valid bearer: every
// X-Auth-* the handler writes equals the corresponding MeshAuthorize field.
// This is the byte-identical contract at the identity layer.
func TestMeshAuthorize_IdentityMatchesHTTPHandler(t *testing.T) {
	srv, httpSrv, login := newMeshAuthorizeServer(t, sso.WithMeshExtAuthz(""))
	bearer := login([]string{"openid", "profile"})

	// Direct decision.
	res := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    httpSrv.URL + sso.PathMeshExtAuthz,
		Header: bearerHeader(bearer),
	})
	if !res.Allowed {
		t.Fatalf("MeshAuthorize denied a valid bearer: %q", res.DenyCode)
	}

	// HTTP handler over the same bearer.
	req, _ := http.NewRequest(http.MethodGet, httpSrv.URL+sso.PathMeshExtAuthz, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	hResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http ext_authz: %v", err)
	}
	defer func() { _ = hResp.Body.Close() }()
	if hResp.StatusCode != http.StatusOK {
		t.Fatalf("http status = %d want 200", hResp.StatusCode)
	}

	if got, want := hResp.Header.Get(sso.HeaderAuthSubject), res.Subject; got != want {
		t.Errorf("X-Auth-Subject = %q but MeshAuthorize.Subject = %q", got, want)
	}
	if got, want := hResp.Header.Get(sso.HeaderAuthClientID), res.ClientID; got != want {
		t.Errorf("X-Auth-Client-Id = %q but MeshAuthorize.ClientID = %q", got, want)
	}
	if got, want := hResp.Header.Get(sso.HeaderAuthScopes), strings.Join(res.Scopes, " "); got != want {
		t.Errorf("X-Auth-Scopes = %q but MeshAuthorize.Scopes joined = %q", got, want)
	}
	if got, want := hResp.Header.Get(sso.HeaderAuthExpires), strconv.FormatInt(res.ExpiresAt, 10); got != want {
		t.Errorf("X-Auth-Expires = %q but MeshAuthorize.ExpiresAt = %q", got, want)
	}
}

// TestMeshAuthorize_Residency_DisallowedRegionDenies proves the read-side
// data-residency gate fires through the seam: a VALID token for a
// region-constrained tenant is DENIED (invalid_token, oracle-safe — no
// identity) when MeshAuthorize sees a disallowed serving region, and ALLOWED
// from the tenant's home region. The serving region is re-resolved inside
// MeshAuthorize (stashMeshServingRegion) from the X-Serving-Region header on
// the request, exactly as region.Middleware would on the HTTP path — so the
// gate is not bypassable through the gRPC-shaped entry point.
func TestMeshAuthorize_Residency_DisallowedRegionDenies(t *testing.T) {
	const srvRegionHeader = "X-Serving-Region"
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: meshUser, Email: "mesh@example.com"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: meshClient, Secret: meshSecret, Active: true,
		TenantID:              residencyTenantID, // eu-west-1 home, eu-west-1 only
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
	tstore := tenantmemory.New()
	if err := tstore.PutTenant(context.Background(), residencyTenant(true)); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.test"),
		defaultimpl.WithEd25519TokenTTL(2*time.Minute),
	)
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantStore(tstore),
		sso.WithMeshExtAuthz(""),
		sso.WithRegionMiddleware(region.HeaderResolver{
			Header:  srvRegionHeader,
			Default: "eu-west-1", // home region when the header is absent
		}, region.MiddlewareOptions{}),
		sso.WithTenantResidencyCheck(0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Mint a token from the HOME region (no serving header on the login) so
	// issuance succeeds — the read-side gate is what we exercise.
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  meshClient,
		"credential": map[string]string{"username": meshUser, "password": meshPassword},
		"scope":      []string{"openid"},
	})
	lresp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(lresp.Body).Decode(&out)
	_ = lresp.Body.Close()
	bearer, _ := out["access_token"].(string)
	if bearer == "" {
		t.Fatalf("no access_token: %v", out)
	}

	withRegion := func(reg string) http.Header {
		h := bearerHeader(bearer)
		h.Set(srvRegionHeader, reg)
		return h
	}

	// Disallowed serving region → DENY (oracle-safe invalid_token, no identity).
	resDeny := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    "https://sso.test" + sso.PathMeshExtAuthz,
		Header: withRegion("us-east-1"),
	})
	if resDeny.Allowed {
		t.Fatalf("Allowed = true want false (residency-denied region)")
	}
	if resDeny.DenyCode != sso.ErrInvalidToken {
		t.Errorf("DenyCode = %q want invalid_token (oracle-safe)", resDeny.DenyCode)
	}
	if resDeny.Subject != "" {
		t.Errorf("Subject leaked on residency DENY: %q", resDeny.Subject)
	}

	// Home/allowed serving region → ALLOW with derived identity.
	resAllow := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    "https://sso.test" + sso.PathMeshExtAuthz,
		Header: withRegion("eu-west-1"),
	})
	if !resAllow.Allowed {
		t.Fatalf("Allowed = false want true (home region) deny=%q", resAllow.DenyCode)
	}
	if resAllow.Subject != meshUser {
		t.Errorf("Subject = %q want %q", resAllow.Subject, meshUser)
	}
}

// TestMeshAuthorize_DPoPNonceRequired_SurfacesFreshNonce proves the HIGH fix
// at the seam: with a DPoPNonceProvider wired, a DPoP-bound token presented
// with a proof that has the correct htm/htu but NO nonce takes the nonce
// handshake branch — MeshAuthorize returns Allowed=false AND a NON-empty
// DPoPNonce (the fresh server nonce stampDPoPNonce just emitted). That field
// is what lets the gRPC DENY surface the DPoP-Nonce + use_dpop_nonce
// handshake; before the fix the fresh nonce lived only in the unexported
// challengeHeader and a mesh-only DPoP client could never reissue.
//
// To get a DPoP-bound token while a nonce provider is wired, the mint at
// /token itself must complete the nonce dance (harvest the 400's nonce, retry
// with it embedded). The mesh proof is then deliberately nonce-LESS so it
// hits the nonce-required branch.
func TestMeshAuthorize_DPoPNonceRequired_SurfacesFreshNonce(t *testing.T) {
	nonceProvider, err := sso.NewHMACNonceProvider(time.Minute)
	if err != nil {
		t.Fatalf("nonce provider: %v", err)
	}
	srv, httpSrv, _ := newMeshAuthorizeServer(t,
		sso.WithMeshExtAuthz(""),
		sso.WithDPoPNonceProvider(nonceProvider),
	)
	priv, x := dpopGenKey(t)
	access := mintDPoPBoundTokenWithNonce(t, httpSrv, priv, x)

	const meshURL = "https://sso.test" + sso.PathMeshExtAuthz
	fwd := func(tok string) http.Header {
		h := bearerHeader(tok)
		h.Set("X-Forwarded-Proto", "https")
		h.Set("X-Forwarded-Host", "sso.test")
		return h
	}

	// Proof correctly bound to GET meshURL but carrying NO nonce → with a
	// nonce provider wired this is the use_dpop_nonce handshake, not a plain
	// rejection: Allowed=false AND DPoPNonce set.
	h := fwd(access)
	h.Set("DPoP", signDPoPProof(t, priv, x, http.MethodGet, meshURL)) // no nonce claim
	res := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    meshURL,
		Header: h,
	})
	if res.Allowed {
		t.Fatalf("Allowed = true want false (nonce-required handshake is still a DENY)")
	}
	if res.DPoPNonce == "" {
		t.Fatalf("DPoPNonce = empty want the fresh server nonce (the HIGH fix — the gRPC DENY needs it to reissue)")
	}
	// The surfaced nonce must be a real, server-verifiable nonce (the same one
	// the client copies into its next proof), not a placeholder.
	if verr := nonceProvider.Verify(res.DPoPNonce); verr != nil {
		t.Errorf("surfaced DPoPNonce does not Verify against the provider: %v", verr)
	}
	// Still oracle-safe at the wire-code layer: the HTTP DenyCode stays
	// invalid_token (the HTTP path renders use_dpop_nonce from challengeHeader,
	// not DenyCode), and no identity leaks.
	if res.DenyCode != sso.ErrInvalidToken {
		t.Errorf("DenyCode = %q want invalid_token (HTTP wire-code class unchanged)", res.DenyCode)
	}
	if res.Subject != "" {
		t.Errorf("Subject leaked on the nonce-handshake DENY: %q", res.Subject)
	}

	// Positive control: embed a VALID nonce in the proof → ALLOW, proving the
	// deny above was the missing nonce and the token+key are otherwise good.
	nonce, err := nonceProvider.Issue()
	if err != nil {
		t.Fatalf("issue control nonce: %v", err)
	}
	hOK := fwd(access)
	hOK.Set("DPoP", signDPoPProof(t, priv, x, http.MethodGet, meshURL, func(p map[string]any) {
		p["nonce"] = nonce
	}))
	resOK := srv.MeshAuthorize(context.Background(), sso.MeshAuthorizeRequest{
		Method: http.MethodGet,
		URL:    meshURL,
		Header: hOK,
	})
	if !resOK.Allowed {
		t.Fatalf("Allowed = false want true (valid nonce in proof) deny=%q nonce=%q", resOK.DenyCode, resOK.DPoPNonce)
	}
	if resOK.DPoPNonce != "" {
		t.Errorf("DPoPNonce = %q want empty on ALLOW", resOK.DPoPNonce)
	}
}

// TestMeshAuthorize_HTTPNonceResponseByteIdentical proves the HTTP-mode nonce
// response is UNCHANGED by the new DPoPNonce field: the HTTP handler still
// emits the DPoP-Nonce header + a use_dpop_nonce WWW-Authenticate challenge +
// 401 for a DPoP-bound token whose proof lacks a nonce — driven entirely off
// the replayed challengeHeader, NOT the new DPoPNonce result field (which the
// HTTP path ignores). This locks the byte-identical HTTP guarantee for the
// fix's touched branch.
func TestMeshAuthorize_HTTPNonceResponseByteIdentical(t *testing.T) {
	nonceProvider, err := sso.NewHMACNonceProvider(time.Minute)
	if err != nil {
		t.Fatalf("nonce provider: %v", err)
	}
	_, httpSrv, _ := newMeshAuthorizeServer(t,
		sso.WithMeshExtAuthz(""),
		sso.WithDPoPNonceProvider(nonceProvider),
	)
	priv, x := dpopGenKey(t)
	access := mintDPoPBoundTokenWithNonce(t, httpSrv, priv, x)

	// Drive the real HTTP ext_authz endpoint with a nonce-less proof bound to
	// the actual request URL (requestURLForDPoP rebuilds it from the test
	// server's host; no X-Forwarded-* needed since the request hits httpSrv
	// directly).
	meshURL := httpSrv.URL + sso.PathMeshExtAuthz
	req, _ := http.NewRequest(http.MethodGet, meshURL, nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("DPoP", signDPoPProof(t, priv, x, http.MethodGet, meshURL)) // no nonce
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http ext_authz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d want 401 (nonce required), body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get(sso.HeaderDPoPNonce); got == "" {
		t.Errorf("DPoP-Nonce header empty on the HTTP nonce challenge (must be unchanged by the fix)")
	}
	if wa := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, `error="use_dpop_nonce"`) {
		t.Errorf("WWW-Authenticate = %q want use_dpop_nonce (HTTP nonce response unchanged)", wa)
	}
	// Body stays empty + no identity leaks (oracle-safe, unchanged).
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("body = %q want empty", body)
	}
	if resp.Header.Get(sso.HeaderAuthSubject) != "" {
		t.Errorf("X-Auth-Subject leaked on the nonce-handshake DENY")
	}
}

// --- helpers ---

func meshContains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// mintDPoPBoundToken mints a DPoP-bound access token via client_credentials +
// a DPoP proof (a fresh ephemeral key). Returns the access token.
func mintDPoPBoundToken(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	priv, x := dpopGenKey(t)
	return mintDPoPBoundTokenWithKey(t, srv, priv, x)
}

// mintDPoPBoundTokenWithKey is mintDPoPBoundToken with a caller-supplied key,
// so the caller can later sign matching/mismatching proofs with the same key.
func mintDPoPBoundTokenWithKey(t *testing.T, srv *httptest.Server, priv ed25519.PrivateKey, x string) string {
	t.Helper()
	form := "grant_type=client_credentials&client_id=" + meshClient +
		"&client_secret=" + meshSecret + "&scope=openid"
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", signDPoPProof(t, priv, x, http.MethodPost, srv.URL+"/token"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	rb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out["token_type"] != "DPoP" {
		t.Fatalf("expected DPoP-bound token, got %v", out)
	}
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %s", rb)
	}
	return access
}

// mintDPoPBoundTokenWithNonce mints a DPoP-bound access token at /token while
// a DPoPNonceProvider is wired: it runs the RFC 9449 §8 two-step nonce dance
// (first request harvests the fresh nonce from the 400 use_dpop_nonce
// challenge; the retry embeds it), since /token itself demands the nonce when
// a provider is installed. Returns the access token, bound to (priv, x).
func mintDPoPBoundTokenWithNonce(t *testing.T, srv *httptest.Server, priv ed25519.PrivateKey, x string) string {
	t.Helper()
	form := "grant_type=client_credentials&client_id=" + meshClient +
		"&client_secret=" + meshSecret + "&scope=openid"
	tokenURL := srv.URL + "/token"

	// Step 1: nonce-less request → 400 carrying a fresh DPoP-Nonce.
	req1, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.Header.Set("DPoP", signDPoPProof(t, priv, x, http.MethodPost, tokenURL))
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("token step 1: %v", err)
	}
	nonce := resp1.Header.Get(sso.HeaderDPoPNonce)
	_ = resp1.Body.Close()
	if nonce == "" {
		t.Fatalf("token step 1 yielded no DPoP-Nonce (nonce provider not enforcing?)")
	}

	// Step 2: retry with the nonce embedded → 200 + DPoP-bound token.
	req2, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("DPoP", signDPoPProof(t, priv, x, http.MethodPost, tokenURL, func(p map[string]any) {
		p["nonce"] = nonce
	}))
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("token step 2: %v", err)
	}
	rb, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out["token_type"] != "DPoP" {
		t.Fatalf("expected DPoP-bound token, got %v (body=%s)", out, rb)
	}
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %s", rb)
	}
	return access
}
