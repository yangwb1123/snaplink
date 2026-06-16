package sso_test

// rootcov2_login_test.go drives the login orchestrator (login_handler.go
// handleLogin + finish_login.go finishLogin) through its richer parameter
// branches the first rootcov_* pass left thin: RAR (authorization_details),
// the OIDC `claims` parameter, nonce, acr_values, ui_locales, and the
// form_post response mode (discovery_handler.go renderFormPostResponse /
// isValidResponseMode). It also covers the self-service session/consent
// management endpoints (me_sessions.go) and the public discovery-cache
// invalidation seam (discovery_cache.go InvalidateDiscoveryCache).
//
// REUSES rcovNewServer / rcovDirectLogin / rcovPostJSON / rcovDo / rcovGetJSON
// and rcov2PasswordAuth.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/fapi"
)

// TestRcov2L_RichLogin exercises a direct-mint login carrying RAR
// authorization_details, the claims parameter, nonce, acr_values, and
// ui_locales — driving the finishLogin RAR-validation + claims-threading
// branches.
func TestRcov2L_RichLogin(t *testing.T) {
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, RedirectURIs: []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
		AllowedAuthorizationDetailsTypes: []string{"payment_initiation"},
	})
	// The authenticator achieves urn:acr:1 so the acr_values demand is met.
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{UserID: rcovUser, AuthMethods: []string{"pwd"}, AchievedACR: "urn:acr:1"}, nil
			}
			return nil, context.Canceled
		}))
	iss := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithSupportedACRValues("urn:acr:1"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile"},
		"nonce":      "n-0S6_WzA2Mj",
		"acr_values": "urn:acr:1",
		"ui_locales": "en-US fr-CA",
		"authorization_details": []map[string]any{
			{"type": "payment_initiation", "actions": []string{"read"}},
		},
		"claims": map[string]any{
			"id_token": map[string]any{"email": map[string]any{"essential": true}},
		},
	})
	if status != http.StatusOK {
		t.Fatalf("rich login = %d body=%v", status, out)
	}
	if out["access_token"] == "" || out["access_token"] == nil {
		t.Errorf("rich login minted no token: %v", out)
	}
	if out["id_token"] == "" || out["id_token"] == nil {
		t.Errorf("rich login (openid) minted no id_token: %v", out)
	}

	// RAR with a type NOT in the client's allowlist => rejected.
	status, out = rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"authorization_details": []map[string]any{
			{"type": "account_information"},
		},
	})
	if status != http.StatusBadRequest {
		t.Errorf("RAR disallowed type = %d, want 400 (body=%v)", status, out)
	}
}

// TestRcov2L_FormPostResponseMode covers the code login with
// response_mode=form_post: finishLogin renders an HTML auto-POST page
// (renderFormPostResponse) instead of a JSON body.
func TestRcov2L_FormPostResponseMode(t *testing.T) {
	s := rcovNewServer(t)

	body := map[string]any{
		"provider":      "password",
		"client_id":     rcovClient,
		"credential":    map[string]string{"username": rcovUsername, "password": rcovPassword},
		"response_type": "code",
		"redirect_uri":  rcovRedirect,
		"response_mode": "form_post",
		"state":         "fp-state",
	}
	// Use a raw request so we can inspect the HTML body + content type.
	status, _ := rcovPostJSON(t, s.http.URL+"/auth/login", "", body)
	if status != http.StatusOK {
		t.Fatalf("form_post login = %d", status)
	}

	resp := rcov2PostRaw(t, s.http.URL+"/auth/login", body)
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("form_post Content-Type = %q, want text/html", ct)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "<form") {
		t.Errorf("form_post body is not an auto-POST form: %q", string(raw)[:min(120, len(raw))])
	}

	// An unknown response_mode is rejected.
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":      "password",
		"client_id":     rcovClient,
		"credential":    map[string]string{"username": rcovUsername, "password": rcovPassword},
		"response_type": "code",
		"redirect_uri":  rcovRedirect,
		"response_mode": "totally-bogus-mode",
	})
	if status != http.StatusBadRequest {
		t.Errorf("bogus response_mode = %d, want 400 (body=%v)", status, out)
	}
}

// rcov2PostRaw posts a JSON body and returns the raw response for body/header
// inspection (the form_post path returns HTML, not JSON, so the shared
// JSON-decoding helpers can't be used).
func rcov2PostRaw(t *testing.T, url string, body map[string]any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// TestRcov2L_FAPIInspection wires the FAPI 2.0 profile in inspection mode and
// drives a login through the FAPI validation path (handleLogin FAPI branch).
func TestRcov2L_FAPIInspection(t *testing.T) {
	s := rcovNewServer(t, sso.WithFAPIProfile(fapi.ModeInspection))

	// Inspection mode never blocks — it records violations as metrics; the
	// login still mints. This drives the FAPI branch in handleLogin.
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":      "password",
		"client_id":     rcovClient,
		"credential":    map[string]string{"username": rcovUsername, "password": rcovPassword},
		"response_type": "code",
		"redirect_uri":  rcovRedirect,
	})
	if status != http.StatusOK {
		t.Fatalf("FAPI-inspection login = %d body=%v", status, out)
	}
}

// TestRcov2L_MeSessionsAndConsents covers the self-service session + consent
// management endpoints: list/revoke-all sessions, list/delete consents.
func TestRcov2L_MeSessionsAndConsents(t *testing.T) {
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	// Seed a consent grant so the consent endpoints have something to return.
	_ = s.consents.RecordConsent(context.Background(), sso.ConsentGrant{
		UserID: rcovUser, ClientID: rcovClient, Scopes: []string{"openid", "profile"},
		GrantedAt: time.Now(),
	})

	// List sessions.
	status, _ := rcovDo(t, http.MethodGet, s.http.URL+"/sessions/me", access, nil)
	if status != http.StatusOK {
		t.Errorf("list sessions = %d, want 200", status)
	}

	// List consents (the seeded grant appears).
	status, list := rcovDo(t, http.MethodGet, s.http.URL+"/consents/me", access, nil)
	if status != http.StatusOK {
		t.Errorf("list consents = %d body=%v, want 200", status, list)
	}

	// Delete the consent for the client.
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/consents/me/"+rcovClient, access, nil)
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Errorf("delete consent = %d, want 200/204", status)
	}

	// Revoke all of my sessions (logout everywhere from the session side).
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/sessions/me", access, nil)
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Errorf("revoke all my sessions = %d, want 200/204", status)
	}
}

// TestRcov2L_DiscoveryCacheInvalidate covers the public InvalidateDiscoveryCache
// seam: fetch the doc (populates the cache), invalidate, fetch again.
func TestRcov2L_DiscoveryCacheInvalidate(t *testing.T) {
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDiscoveryCacheTTL(5*time.Second),
		sso.WithDiscoveryDocCacheTTL(5*time.Second),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Populate the snapshot + body caches.
	resp := rcovGetJSON(t, httpSrv.URL+"/.well-known/openid-configuration", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery = %d", resp.StatusCode)
	}
	// Invalidate (the seam an operator wires into config-changing admin RPCs).
	srv.InvalidateDiscoveryCache()
	// Re-fetch recomputes from server state.
	resp = rcovGetJSON(t, httpSrv.URL+"/.well-known/openid-configuration", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("discovery after invalidate = %d, want 200", resp.StatusCode)
	}
}
