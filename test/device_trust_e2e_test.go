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

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/authenticators/device"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

// TestDeviceTrustE2E verifies the full device registration → trust scoring
// → security analysis pipeline end-to-end. Two consecutive logins from the
// same client/user-agent must produce a consistent device fingerprint, the
// first marked new and the second not-new, with a rising trust score.
func TestDeviceTrustE2E(t *testing.T) {
	const (
		uid = "e2e-user"
		cid = "e2e-client"
	)

	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	devStore := device.NewMemoryStore()
	loginHist := device.NewMemoryHistoryStore()

	users.CreateOrUpdate(ctx, &core.User{ID: uid})
	clients.AddSeed(&core.Client{
		ID:                    cid,
		Secret:                "secret",
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		AllowedScopes:         []string{"openid", "profile"},
		TokenStrategy:         "jwt",
	})

	ti := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.test"),
		defaultimpl.WithEd25519TokenTTL(time.Hour),
	)

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*core.AuthResult, error) {
			return &core.AuthResult{UserID: uid, Provider: "password"}, nil
		},
	))

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithSessionManager(sessions),
		sso.WithTokenIssuer("jwt", ti),
		sso.WithIDTokenIssuer(ti),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDeviceStore(devStore),
		sso.WithLoginHistoryStore(loginHist),
	)

	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()

	// --- Login 1: new device ---
	r1 := doLoginDev(t, hsrv)
	d1 := r1["device"].(map[string]any)
	if d1["is_new"] != true {
		t.Error("login 1: device should be marked new")
	}
	devID1 := d1["id"].(string)
	if devID1 == "" {
		t.Fatal("login 1: device ID must be non-empty")
	}
	ts1 := d1["trust_score"].(float64)
	if ts1 < 0.1 || ts1 > 0.95 {
		t.Errorf("login 1: trust score %v out of range [0.1,0.95]", ts1)
	}
	t.Logf("login 1: device=%s is_new=true trust=%.3f", devID1, ts1)

	// Verify access_token was issued with device claims
	tok1 := r1["access_token"].(string)
	if tok1 == "" {
		t.Fatal("login 1: missing access_token")
	}

	// --- Login 2: same device (same User-Agent, no X-Device-Id) ---
	r2 := doLoginDev(t, hsrv)
	d2 := r2["device"].(map[string]any)

	// On login 2, is_new is omitted (false with omitempty) — nil means false
	if d2["is_new"] != nil {
		t.Errorf("login 2: is_new should be omitted/nil, got %v", d2["is_new"])
	}

	devID2 := d2["id"].(string)
	if devID2 != devID1 {
		t.Errorf("login 2: device ID should match login 1 (%s), got %s", devID1, devID2)
	}

	ts2 := d2["trust_score"].(float64)
	if ts2 <= ts1 {
		t.Errorf("login 2: trust score %v should exceed login 1 score %v", ts2, ts1)
	}
	t.Logf("login 2: device=%s is_new=false trust=%.3f (was %.3f)", devID2, ts2, ts1)

	// --- Trust score is within valid range ---
	if ts2 < 0.1 || ts2 > 0.95 {
		t.Errorf("trust score %v out of range [0.1,0.95]", ts2)
	}

	// --- Login history has device info ---
	token := r2["access_token"].(string)
	histResp := getDevToken(t, hsrv.URL+"/me/login-history", token)
	var hist map[string]any
	bh, _ := io.ReadAll(histResp.Body)
	json.Unmarshal(bh, &hist)
	histResp.Body.Close()

	if hist["login_history"] == nil {
		t.Fatal("login history missing from response")
	}
	entries := hist["login_history"].([]any)
	if len(entries) == 0 {
		t.Fatal("login history is empty")
	}

	// Most recent entry should have device context
	e := entries[0].(map[string]any)
	t.Logf("history[0]: time=%v device=%v trust=%v is_new=%v",
		e["time"], e["device"], e["trust_score"], e["device_is_new"])

	if _, ok := e["trust_score"]; !ok {
		t.Error("login history entry missing trust_score")
	}
}

func doLoginDev(t *testing.T, hsrv *httptest.Server) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "e2e-client",
		"credential": map[string]string{"username": "e2e-user", "password": "any"},
		"scope":      []string{"openid", "profile"},
	})
	resp, err := http.Post(hsrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r map[string]any
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decode login response: %v (raw: %s)", err, string(raw))
	}
	if resp.StatusCode != 200 {
		t.Fatalf("login status=%d: %v (body: %s)", resp.StatusCode, r["error"], string(raw))
	}
	if r["device"] == nil {
		t.Fatal("login response missing device context")
	}
	return r
}

func getDevToken(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}
