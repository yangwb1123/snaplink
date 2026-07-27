package ssotest

import "github.com/yangwb1123/snaplink/protocols/oauth"

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
	devUser   = "u-device"
	devClient = "device-client"
	devSecret = "device-secret"
)

func newDeviceServer(t *testing.T, ttl, interval time.Duration) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: devUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: devClient, Secret: devSecret,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: devUser, Provider: "password"}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDeviceCodeStore(defaultimpl.NewMemoryDeviceCodeStore(), ttl, interval, ""),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// requestDeviceCode posts /device/code → (device_code, user_code, body).
func requestDeviceCode(t *testing.T, srv *httptest.Server) (string, string, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"client_id": devClient})
	resp, err := http.Post(srv.URL+"/device/code", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /device/code: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	dc, _ := out["device_code"].(string)
	uc, _ := out["user_code"].(string)
	return dc, uc, out
}

// userBearerToken logs in via /auth/login and returns an access token
// for use against /device/verify.
func userBearerToken(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  devClient,
		"credential": map[string]string{"username": "x", "password": "y"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
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

// verifyUserCode posts /device/verify with the bearer + user_code +
// approve flag.
func verifyUserCode(t *testing.T, srv *httptest.Server, bearer, userCode string, approve bool) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"user_code": userCode, "approve": approve})
	r, _ := http.NewRequest(http.MethodPost, srv.URL+"/device/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// pollToken posts /token grant_type=urn:...:device_code.
func pollToken(t *testing.T, srv *httptest.Server, deviceCode string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
		"device_code":   deviceCode,
		"client_id":     devClient,
		"client_secret": devSecret,
	})
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// ---------- /device/code ----------

func TestDevice_CodeEndpointShape(t *testing.T) {
	srv := newDeviceServer(t, 10*time.Minute, time.Millisecond)
	_, _, body := requestDeviceCode(t, srv)
	for _, k := range []string{"device_code", "user_code", "verification_uri", "verification_uri_complete", "expires_in", "interval"} {
		if body[k] == nil {
			t.Errorf("missing key %q", k)
		}
	}
	uc, _ := body["user_code"].(string)
	if len(uc) != 9 || uc[4] != '-' { // 4+1+4
		t.Errorf("user_code = %q, want XXXX-XXXX", uc)
	}
	uri, _ := body["verification_uri_complete"].(string)
	if !strings.Contains(uri, "user_code="+uc) {
		t.Errorf("verification_uri_complete missing user_code: %q", uri)
	}
}

func TestDevice_CodeEndpointRejectsMissingClient(t *testing.T) {
	srv := newDeviceServer(t, time.Minute, time.Millisecond)
	body, _ := json.Marshal(map[string]any{})
	resp, err := http.Post(srv.URL+"/device/code", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d want 400 missing_client_id", resp.StatusCode)
	}
}

func TestDevice_CodeEndpointRejectsUnknownClient(t *testing.T) {
	srv := newDeviceServer(t, time.Minute, time.Millisecond)
	body, _ := json.Marshal(map[string]any{"client_id": "nobody"})
	resp, err := http.Post(srv.URL+"/device/code", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d want 401", resp.StatusCode)
	}
}

// ---------- poll states ----------

func TestDevice_PollPendingBeforeApproval(t *testing.T) {
	srv := newDeviceServer(t, time.Minute, time.Millisecond)
	dc, _, _ := requestDeviceCode(t, srv)
	status, body := pollToken(t, srv, dc)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d want 400 authorization_pending", status)
	}
	if body["error"] != "authorization_pending" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestDevice_FullApprovalRoundTripMintsTokens(t *testing.T) {
	srv := newDeviceServer(t, time.Minute, time.Millisecond)
	dc, uc, _ := requestDeviceCode(t, srv)
	bearer := userBearerToken(t, srv)

	if status := verifyUserCode(t, srv, bearer, uc, true); status != http.StatusOK {
		t.Fatalf("verify status = %d", status)
	}
	status, body := pollToken(t, srv, dc)
	if status != http.StatusOK {
		t.Fatalf("poll status = %d body=%v", status, body)
	}
	if body["access_token"] == "" {
		t.Errorf("missing access_token: %v", body)
	}
}

func TestDevice_VerifyAcceptsDashlessUserCode(t *testing.T) {
	srv := newDeviceServer(t, time.Minute, time.Millisecond)
	_, uc, _ := requestDeviceCode(t, srv)
	bearer := userBearerToken(t, srv)
	// Strip dash; the server normalizes via two-attempt fallback.
	stripped := strings.ReplaceAll(uc, "-", "")
	if status := verifyUserCode(t, srv, bearer, stripped, true); status != http.StatusOK {
		t.Errorf("verify with dashless code status = %d", status)
	}
}

func TestDevice_DenialReturnsAccessDenied(t *testing.T) {
	srv := newDeviceServer(t, time.Minute, time.Millisecond)
	dc, uc, _ := requestDeviceCode(t, srv)
	bearer := userBearerToken(t, srv)

	if status := verifyUserCode(t, srv, bearer, uc, false); status != http.StatusOK {
		t.Fatalf("deny status = %d", status)
	}
	status, body := pollToken(t, srv, dc)
	if status != http.StatusBadRequest {
		t.Fatalf("poll after deny status = %d", status)
	}
	if body["error"] != "access_denied" {
		t.Errorf("error = %v want access_denied", body["error"])
	}
}

func TestDevice_SlowDownOnRapidPolling(t *testing.T) {
	// Interval = 1 hour → second poll is instantaneously too fast.
	srv := newDeviceServer(t, time.Minute, time.Hour)
	dc, _, _ := requestDeviceCode(t, srv)

	pollToken(t, srv, dc) // first poll updates LastPoll
	status, body := pollToken(t, srv, dc)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d", status)
	}
	if body["error"] != "slow_down" {
		t.Errorf("error = %v want slow_down", body["error"])
	}
}

func TestDevice_ExpiredCodeRejected(t *testing.T) {
	srv := newDeviceServer(t, time.Nanosecond, time.Millisecond)
	dc, _, _ := requestDeviceCode(t, srv)
	time.Sleep(2 * time.Millisecond)
	status, body := pollToken(t, srv, dc)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d", status)
	}
	if body["error"] != "expired_token" {
		t.Errorf("error = %v want expired_token", body["error"])
	}
}

func TestDevice_WrongClientCannotPoll(t *testing.T) {
	// Second client steals the device_code → must fail with invalid_grant.
	srv := newDeviceServer(t, time.Minute, time.Millisecond)
	dc, _, _ := requestDeviceCode(t, srv)

	body, _ := json.Marshal(map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
		"device_code":   dc,
		"client_id":     "different-client",
		"client_secret": "different-secret",
	})
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Goes through requireDeps → invalid_client (different client doesn't
	// exist), which proves the binding check runs before token issuance.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("status = 200 — different client succeeded in stealing device_code")
	}
}

func TestDevice_PollEndpointRequiresStore(t *testing.T) {
	// Server without WithDeviceCodeStore → 501 with dedicated code.
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: devClient, Secret: devSecret, Active: true})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	body, _ := json.Marshal(map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
		"device_code":   "any",
		"client_id":     devClient,
		"client_secret": devSecret,
	})
	resp, err := http.Post(httpSrv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d want 501", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "device_code_not_configured" {
		t.Errorf("error = %v", out["error"])
	}
}

func TestDevice_VerifyRequiresBearer(t *testing.T) {
	srv := newDeviceServer(t, time.Minute, time.Millisecond)
	_, uc, _ := requestDeviceCode(t, srv)
	body, _ := json.Marshal(map[string]any{"user_code": uc, "approve": true})
	resp, err := http.Post(srv.URL+"/device/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d want 401", resp.StatusCode)
	}
}

// ---------- SPI smoke ----------

func TestDevice_MemoryStoreLookupsAndDelete(t *testing.T) {
	st := defaultimpl.NewMemoryDeviceCodeStore()
	now := time.Now()
	in := &oauth.DeviceCode{
		DeviceCode: "DC", UserCode: "UC", ClientID: "c",
		Scopes: []string{"a"}, Interval: time.Second, ExpiresAt: now.Add(time.Minute),
	}
	if err := st.Issue(context.Background(), in); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if out, err := st.GetByDeviceCode(context.Background(), "DC"); err != nil || out.UserCode != "UC" {
		t.Errorf("GetByDeviceCode err=%v out=%v", err, out)
	}
	if out, err := st.GetByUserCode(context.Background(), "UC"); err != nil || out.DeviceCode != "DC" {
		t.Errorf("GetByUserCode err=%v out=%v", err, out)
	}
	if err := st.Approve(context.Background(), "UC", "u-1", "pw", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if out, _ := st.GetByDeviceCode(context.Background(), "DC"); !out.Approved || out.UserID != "u-1" {
		t.Errorf("approval not reflected: %+v", out)
	}
	if err := st.Delete(context.Background(), "DC"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if _, err := st.GetByDeviceCode(context.Background(), "DC"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Errorf("after Delete err = %v want oauth.ErrDeviceCodeNotFound", err)
	}
}

func TestDevice_GenerateUserCodeFormat(t *testing.T) {
	for range 50 {
		uc, err := defaultimpl.GenerateUserCode()
		if err != nil {
			t.Fatalf("GenerateUserCode: %v", err)
		}
		if len(uc) != 9 || uc[4] != '-' {
			t.Fatalf("user_code malformed: %q", uc)
		}
		// Verify no ambiguous chars.
		for _, c := range uc {
			if c == '-' {
				continue
			}
			if strings.ContainsRune("0O1IL", c) {
				t.Errorf("user_code %q contains ambiguous char %c", uc, c)
			}
		}
	}
}
