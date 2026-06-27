package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oauth"
)

// newRefreshClaimsServer wires an auth-code store AND a server-managed refresh
// token store so the test can drive a full code-exchange -> refresh-rotation
// chain over HTTP. Mirrors newCodeFlowServer but adds WithRefreshTokenStore.
func newRefreshClaimsServer(t *testing.T) (*httptest.Server, *defaultimpl.MemoryAuthCodeStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: codeUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: codeClient, Secret: codeSecret, Name: "Refresh Claims",
		RedirectURIs: []string{codeRedirectURI}, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true,
	})
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	store := defaultimpl.NewMemoryAuthCodeStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(store, 5*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, store
}

func exchangeRefresh(t *testing.T, srv *httptest.Server, refresh string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     codeClient,
		"client_secret": codeSecret,
	})
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("refresh token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// TestRefreshRotation_PreservesAMRACRAuthTime is the regression guard for the
// RFC 9068 §2.2 / AGENTS.md §3 invariant "Refresh: propagates original AMR
// without resetting AuthTime". A rotated access token MUST carry the SAME
// multi-valued amr + acr + auth_time as the original authentication event —
// not amr collapsed to the single provider id, acr dropped, and auth_time
// reset to the exchange moment (the pre-fix bug that silently down-trusted
// every post-refresh request for MFA/step-up resource servers).
func TestRefreshRotation_PreservesAMRACRAuthTime(t *testing.T) {
	srv, store := newRefreshClaimsServer(t)

	// A fixed past auth_time so we can prove the rotation does NOT reset it to
	// the exchange moment. Second-granularity (JWT auth_time is unix seconds).
	seedAuthTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	const code = "code-rotation-amr"
	if err := store.Issue(context.Background(), code, &oauth.AuthCode{
		UserID: codeUser, ClientID: codeClient, RedirectURI: codeRedirectURI,
		Scopes:      []string{"openid"},
		Provider:    "password",
		AuthMethods: []string{"pwd", "otp", "mfa"},
		ACR:         "urn:acr:high",
		AuthTime:    seedAuthTime,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("seed auth code: %v", err)
	}

	// 1) Code exchange -> access token + server-managed refresh token.
	status, body := exchangeCode(t, srv, code, codeRedirectURI, codeClient, codeSecret)
	if status != http.StatusOK {
		t.Fatalf("code exchange status=%d body=%v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token issued at code exchange: %v", body)
	}

	// 2) Refresh rotation -> a NEW access token. This is the path that used to
	// drop the auth context.
	status, body = exchangeRefresh(t, srv, refresh)
	if status != http.StatusOK {
		t.Fatalf("refresh rotation status=%d body=%v", status, body)
	}
	rotated, _ := body["access_token"].(string)
	if rotated == "" {
		t.Fatalf("no access_token after rotation: %v", body)
	}
	claims := jwtAllClaims(t, rotated)

	amr := jwtStringSlice(claims["amr"])
	if len(amr) != 3 || amr[0] != "pwd" || amr[1] != "otp" || amr[2] != "mfa" {
		t.Errorf("rotated amr = %v, want [pwd otp mfa] (NOT collapsed to provider)", claims["amr"])
	}
	if acr, _ := claims["acr"].(string); acr != "urn:acr:high" {
		t.Errorf("rotated acr = %v, want urn:acr:high (NOT dropped)", claims["acr"])
	}
	authTime, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("rotated token missing auth_time claim: %v", claims["auth_time"])
	}
	if int64(authTime) != seedAuthTime.Unix() {
		t.Errorf("rotated auth_time = %d, want the ORIGINAL %d (NOT reset to the exchange moment)",
			int64(authTime), seedAuthTime.Unix())
	}
}
