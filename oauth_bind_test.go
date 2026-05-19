package sso_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// ---------- harness ----------

const (
	formClientID = "form-client"
	formSecret   = "form-secret-value"
	formUserID   = "u-form"
)

func newFormHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: formUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: formClientID, Secret: formSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: formUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func loginFormHarness(t *testing.T, srv *httptest.Server) (access, refresh string) {
	t.Helper()
	body := strings.NewReader(url.Values{
		"provider":  {"password"},
		"client_id": {formClientID},
	}.Encode())
	// Login still uses JSON; build a JSON post here directly.
	jsonBody := `{"provider":"password","client_id":"` + formClientID +
		`","credential":{"username":"x","password":"y"}}`
	_ = body
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	access, _ = out["access_token"].(string)
	refresh, _ = out["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens in login: %s", raw)
	}
	return access, refresh
}

func postForm(t *testing.T, srv *httptest.Server, path string, vals url.Values, basic [2]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic[0] != "" {
		req.SetBasicAuth(basic[0], basic[1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// ---------- /token form-encoded ----------

func TestFormEncoded_TokenClientCredentials(t *testing.T) {
	srv := newFormHarness(t)
	status, body := postForm(t, srv, "/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {formClientID},
		"client_secret": {formSecret},
		"scope":         {"read write"},
	}, [2]string{"", ""})
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v", status, body)
	}
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Errorf("missing access_token in response: %v", body)
	}
	if got := body["scope"]; got != "read write" {
		t.Errorf("scope round-trip = %v, want %q", got, "read write")
	}
}

func TestFormEncoded_TokenRefreshGrant(t *testing.T) {
	srv := newFormHarness(t)
	_, refresh := loginFormHarness(t, srv)

	status, body := postForm(t, srv, "/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {formClientID},
		"client_secret": {formSecret},
		"refresh_token": {refresh},
	}, [2]string{"", ""})
	if status != http.StatusOK {
		t.Fatalf("refresh form: status=%d body=%v", status, body)
	}
	if body["access_token"] == nil {
		t.Errorf("missing access_token on form-encoded refresh: %v", body)
	}
	if body["refresh_token"] == nil {
		t.Errorf("missing rotated refresh_token: %v", body)
	}
}

// ---------- HTTP Basic auth precedence ----------

func TestFormEncoded_BasicAuthOverridesBodyCreds(t *testing.T) {
	srv := newFormHarness(t)
	// Body carries WRONG creds, Basic header carries RIGHT creds.
	// Per RFC 6749 §2.3.1, Basic must win — the call must succeed.
	status, body := postForm(t, srv, "/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"wrong"},
		"client_secret": {"also-wrong"},
	}, [2]string{formClientID, formSecret})
	if status != http.StatusOK {
		t.Fatalf("Basic should override bad body creds: status=%d body=%v", status, body)
	}
	if body["access_token"] == nil {
		t.Errorf("missing access_token: %v", body)
	}
}

func TestFormEncoded_BasicAuthAlsoAcceptedRaw(t *testing.T) {
	// Verify the http.SetBasicAuth helper produces the same header the
	// server reads. Direct b64-encoded header construction, no helper.
	srv := newFormHarness(t)
	cred := base64.StdEncoding.EncodeToString([]byte(formClientID + ":" + formSecret))
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token",
		strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+cred)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// ---------- /token/introspect form-encoded ----------

func TestFormEncoded_Introspect(t *testing.T) {
	srv := newFormHarness(t)
	access, _ := loginFormHarness(t, srv)

	status, body := postForm(t, srv, "/token/introspect", url.Values{
		"token":           {access},
		"token_type_hint": {"access_token"},
	}, [2]string{formClientID, formSecret})
	if status != http.StatusOK {
		t.Fatalf("introspect form: status=%d body=%v", status, body)
	}
	if body["active"] != true {
		t.Errorf("expected active=true on a valid token, got %v", body["active"])
	}
}

// ---------- /token/revoke form-encoded ----------

func TestFormEncoded_Revoke(t *testing.T) {
	srv := newFormHarness(t)
	_, refresh := loginFormHarness(t, srv)

	status, _ := postForm(t, srv, "/token/revoke", url.Values{
		"token":           {refresh},
		"token_type_hint": {"refresh_token"},
	}, [2]string{formClientID, formSecret})
	if status != http.StatusOK {
		t.Errorf("revoke form: status=%d (want 200 idempotent)", status)
	}
	// Second revoke of the same token must also 200 per §2.2.
	status2, _ := postForm(t, srv, "/token/revoke", url.Values{
		"token": {refresh},
	}, [2]string{formClientID, formSecret})
	if status2 != http.StatusOK {
		t.Errorf("second revoke status=%d (idempotency violation)", status2)
	}
}

// ---------- /device/code form-encoded ----------

func TestFormEncoded_DeviceCode(t *testing.T) {
	srv := newFormDeviceHarness(t)
	status, body := postForm(t, srv, "/device/code", url.Values{
		"client_id": {formClientID},
		"scope":     {"openid profile"},
	}, [2]string{"", ""})
	if status != http.StatusOK {
		t.Fatalf("device/code form: status=%d body=%v", status, body)
	}
	if body["device_code"] == nil || body["user_code"] == nil {
		t.Errorf("missing device_code/user_code: %v", body)
	}
}

// newFormDeviceHarness mirrors newFormHarness but also wires a
// DeviceCodeStore so /device/code is enabled.
func newFormDeviceHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: formUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: formClientID, Secret: formSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: formUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDeviceCodeStore(defaultimpl.NewMemoryDeviceCodeStore(), 5*time.Minute, 5*time.Second, ""),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// ---------- backward compat: JSON path still works ----------

func TestFormEncoded_JSONStillWorks(t *testing.T) {
	srv := newFormHarness(t)
	body := `{"grant_type":"client_credentials","client_id":"` + formClientID +
		`","client_secret":"` + formSecret + `"}`
	resp, err := http.Post(srv.URL+"/token", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("json post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("json fallback failed: status=%d", resp.StatusCode)
	}
}

// ---------- scope parsing: space-separated single value ----------

func TestFormEncoded_ScopeSpaceSeparated(t *testing.T) {
	// /token's `scope` is a single string field, so this test verifies
	// it round-trips intact. The slice-of-string path in
	// bindOAuthParams kicks in for any future []string scope fields.
	srv := newFormHarness(t)
	status, body := postForm(t, srv, "/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {formClientID},
		"client_secret": {formSecret},
		"scope":         {"openid profile email"},
	}, [2]string{"", ""})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if got, want := body["scope"], "openid profile email"; got != want {
		t.Errorf("scope = %q want %q", got, want)
	}
}
