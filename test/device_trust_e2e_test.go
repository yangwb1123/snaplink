package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/authenticators/device"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

func TestDeviceTrustE2E(t *testing.T) {
	const testUser = "test-user"
	const testClient = "test-client"

	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	devStore := device.NewMemoryStore()
	loginHistory := device.NewMemoryHistoryStore()

	users.CreateOrUpdate(ctx, &core.User{ID: testUser, Email: "test@example.com"})
	clients.AddSeed(&core.Client{
		ID:                    testClient,
		Secret:                "secret",
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		AllowedScopes:         []string{"openid", "profile"},
		TokenStrategy:         "jwt",
	})

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.test"),
		defaultimpl.WithEd25519TokenTTL(time.Hour),
	)

	pwAuth := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: testUser, Provider: "password"}, nil
		},
	))

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pwAuth),
		sso.WithSessionManager(sessions),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDeviceStore(devStore),
		sso.WithLoginHistoryStore(loginHistory),
	)

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// Login 1: new device
	r1 := doLoginDev(t, httpSrv)
	d1 := r1["device"].(map[string]any)
	if d1["is_new"] != true {
		t.Error("login 1: device should be new")
	}
	t.Logf("login 1: device=%v is_new=%v trust=%v", d1["id"], d1["is_new"], d1["trust_score"])

	// Login 2: same device, not new
	r2 := doLoginDev(t, httpSrv)
	d2 := r2["device"].(map[string]any)
	if d2["is_new"] == true {
		t.Error("login 2: device should NOT be new")
	}
	t.Logf("login 2: device=%v is_new=%v trust=%v", d2["id"], d2["is_new"], d2["trust_score"])

	// Verify trust score range
	ts := d2["trust_score"].(float64)
	if ts < 0.1 || ts > 0.95 {
		t.Errorf("trust score out of range [0.1,0.95]: %v", ts)
	}

	// Verify login history has device info
	token := r2["access_token"].(string)
	histResp := getDevToken(t, httpSrv.URL+"/me/login-history", token)
	var hist map[string]any
	json.NewDecoder(histResp.Body).Decode(&hist)
	histResp.Body.Close()
	if hist["login_history"] != nil {
		entries := hist["login_history"].([]any)
		if len(entries) > 0 {
			e := entries[0].(map[string]any)
			t.Logf("login history: device=%v is_new=%v", e["device"], e["device_is_new"])
		}
	}
}

func doLoginDev(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "test-client",
		"credential": map[string]string{"username": "test-user", "password": "any"},
		"scope":      []string{"openid", "profile"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil { t.Fatalf("POST: %v", err) }
	defer resp.Body.Close()
	var r map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d: %v", resp.StatusCode, r["error"])
	}
	if r["device"] == nil {
		t.Fatal("no device context in response")
	}
	return r
}

func getDevToken(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatalf("GET: %v", err) }
	return resp
}
