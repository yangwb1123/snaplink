package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

// regionTokenClient is bound to the pinned eu-west-1 fixture below.
const (
	regionTokenClient   = "region-token-app"
	regionTokenUser     = "u-region-token"
	regionTokenUsername = "alice"
	regionTokenPassword = "pw"
	regionTokenRedirect = "https://app.example/cb"
)

// newRegionTokenServer wires the full mint surface behind a pinned
// eu-west-1 serving region: JWT issuer (Ed25519) for access + ID tokens,
// auth-code + refresh stores, and WithServingRegionAdvertisement so the
// discovery contract matches the minted claim.
func newRegionTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: regionTokenUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    regionTokenClient,
		Secret:                "region-token-secret",
		Name:                  "Region Token App",
		RedirectURIs:          []string{regionTokenRedirect},
		AllowedScopes:         []string{"openid", "profile", "offline_access"},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == regionTokenUsername && p == regionTokenPassword {
				return &sso.AuthResult{
					UserID:     regionTokenUser,
					Provider:   "password",
					Attributes: map[string]string{"email": "alice@example.com"},
				}, nil
			}
			return nil, errors.New("bad")
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5 * time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithRegionMiddleware(region.ConfigPinnedResolver{Region: "eu-west-1"}, region.MiddlewareOptions{}),
		sso.WithServingRegionAdvertisement("eu-west-1"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// regionTokenLogin posts /auth/login (direct mint or code, per responseType)
// and returns the decoded response. scope and extra body keys (e.g. claims)
// are passed through.
func regionTokenLogin(t *testing.T, srv *httptest.Server, responseType string, scope []string, extra map[string]any) map[string]any {
	t.Helper()
	payload := map[string]any{
		"provider":   "password",
		"client_id":  regionTokenClient,
		"credential": map[string]string{"username": regionTokenUsername, "password": regionTokenPassword},
	}
	if responseType != "" {
		payload["response_type"] = responseType
		payload["redirect_uri"] = regionTokenRedirect
		payload["state"] = "xyz"
	}
	if scope != nil {
		payload["scope"] = scope
	}
	for k, v := range extra {
		payload[k] = v
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d body=%s", resp.StatusCode, raw)
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// assertTokensCarryRegion decodes access_token + id_token (when present) and
// asserts both carry serving_region=eu-west-1.
func assertTokensCarryRegion(t *testing.T, out map[string]any) {
	t.Helper()
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token in %v", out)
	}
	if got := decodeJWTPayload(t, access)["serving_region"]; got != "eu-west-1" {
		t.Errorf("access_token serving_region = %v, want eu-west-1", got)
	}
	if idToken, _ := out["id_token"].(string); idToken != "" {
		if got := decodeJWTPayload(t, idToken)["serving_region"]; got != "eu-west-1" {
			t.Errorf("id_token serving_region = %v, want eu-west-1", got)
		}
	}
}

// TestRegionTokenContract_DirectMint pins decision 1 at the wire level: a
// login served by the pinned eu-west-1 middleware mints BOTH tokens with
// serving_region=eu-west-1.
func TestRegionTokenContract_DirectMint(t *testing.T) {
	srv := newRegionTokenServer(t)
	out := regionTokenLogin(t, srv, "", []string{"openid", "profile"}, nil)
	if got := out[sso.KeyServingRegion]; got != "eu-west-1" {
		t.Errorf("login serving_region = %v, want eu-west-1", got)
	}
	assertTokensCarryRegion(t, out)
}

// TestRegionTokenContract_ClaimsParamImmunity pins the OIDC §5.5 immunity:
// an RP-requested claims parameter (which filters the Extra map only) can
// never drop the first-class serving_region field.
func TestRegionTokenContract_ClaimsParamImmunity(t *testing.T) {
	srv := newRegionTokenServer(t)
	out := regionTokenLogin(t, srv, "", []string{"openid", "profile"}, map[string]any{
		"claims": json.RawMessage(`{"id_token": {"email": null}}`),
	})
	assertTokensCarryRegion(t, out)
}

// TestRegionTokenContract_AuthCodeExchangeSurvives pins the exchange path:
// /token mints a FRESH token set with the CURRENT serving region (mint-time
// semantics — the claim survives the exchange because the exchange is served
// by the same pinned region).
func TestRegionTokenContract_AuthCodeExchangeSurvives(t *testing.T) {
	srv := newRegionTokenServer(t)
	out := regionTokenLogin(t, srv, "code", []string{"openid", "profile"}, nil)
	code, _ := out["code"].(string)
	if code == "" {
		t.Fatalf("no code in %v", out)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {regionTokenRedirect},
		"client_id":     {regionTokenClient},
		"client_secret": {"region-token-secret"},
	}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token = %d body=%s", resp.StatusCode, raw)
	}
	exchanged := map[string]any{}
	_ = json.Unmarshal(raw, &exchanged)
	assertTokensCarryRegion(t, exchanged)
}

// TestRegionTokenContract_RefreshRotationRestamps pins the designed
// mint-time semantics: the rotated access token carries the region that
// SERVED the rotation (same pinned region here), NOT a persisted login
// region — so an RS gate sees the claim re-stamped on every rotation.
func TestRegionTokenContract_RefreshRotationRestamps(t *testing.T) {
	srv := newRegionTokenServer(t)
	out := regionTokenLogin(t, srv, "", []string{"openid", "offline_access"}, nil)
	refresh, _ := out["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token in %v", out)
	}
	status, rotated := refreshExchange(t, srv, refresh, "", regionTokenClient, "region-token-secret")
	if status != http.StatusOK {
		t.Fatalf("refresh = %d body=%v", status, rotated)
	}
	rotatedAccess, _ := rotated["access_token"].(string)
	if rotatedAccess == "" {
		t.Fatalf("no access_token after rotation: %v", rotated)
	}
	if got := decodeJWTPayload(t, rotatedAccess)["serving_region"]; got != "eu-west-1" {
		t.Errorf("rotated access_token serving_region = %v, want eu-west-1", got)
	}
}

// TestRegionTokenContract_IntrospectionEchoes pins the RFC 7662 echo: the
// mint region rides the introspection body so an RS can enforce without
// decoding the JWT itself.
func TestRegionTokenContract_IntrospectionEchoes(t *testing.T) {
	srv := newRegionTokenServer(t)
	out := regionTokenLogin(t, srv, "", []string{"openid"}, nil)
	access, _ := out["access_token"].(string)
	form := url.Values{
		"token":           {access},
		"client_id":       {regionTokenClient},
		"client_secret":   {"region-token-secret"},
		"token_type_hint": {"access_token"},
	}
	resp, err := http.Post(srv.URL+"/token/introspect", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect = %d body=%s", resp.StatusCode, raw)
	}
	body := map[string]any{}
	_ = json.Unmarshal(raw, &body)
	if body["active"] != true {
		t.Fatalf("active = %v, want true: %s", body["active"], raw)
	}
	if got := body[sso.KeyServingRegion]; got != "eu-west-1" {
		t.Errorf("introspection serving_region = %v, want eu-west-1", got)
	}
}

// TestRegionTokenContract_RSSDKGate pins decision 3 against a REAL token
// minted by the pinned fixture: local RS validation accepts the in-region
// token and denies it under a mismatched allowlist (fail-closed governance
// sentinel).
func TestRegionTokenContract_RSSDKGate(t *testing.T) {
	srv := newRegionTokenServer(t)
	out := regionTokenLogin(t, srv, "", []string{"openid"}, nil)
	access, _ := out["access_token"].(string)
	// The mint issuer is the Ed25519 issuer's configured value (the
	// default when no WithEd25519Issuer is wired) — read it off the token
	// so this test does not couple to the default string.
	iss, _ := decodeJWTPayload(t, access)["iss"].(string)
	if iss == "" {
		t.Fatal("minted token carries no iss claim")
	}
	cache := rs.NewJWKSCache(rs.IssuerJWKSURL(srv.URL))
	t.Cleanup(cache.Close)
	cfg := rs.Config{
		Issuer:                iss,
		JWKSCache:             cache,
		AllowedServingRegions: []string{"eu-west-1"},
	}
	claims, err := rs.ValidateToken(context.Background(), access, cfg)
	if err != nil {
		t.Fatalf("ValidateToken(in-region): %v", err)
	}
	if claims.ServingRegion != "eu-west-1" {
		t.Errorf("Claims.ServingRegion = %q, want eu-west-1", claims.ServingRegion)
	}

	mismatch := cfg
	mismatch.AllowedServingRegions = []string{"us-east-1"}
	if _, err := rs.ValidateToken(context.Background(), access, mismatch); !errors.Is(err, rs.ErrServingRegionMismatch) {
		t.Fatalf("ValidateToken(out-of-region) err = %v, want ErrServingRegionMismatch", err)
	}
}
