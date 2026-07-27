package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

func keysOf(m map[string]any) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestSelfServiceEndpointsE2E(t *testing.T) {
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	devStore := device.NewMemoryStore()
	loginHist := device.NewMemoryHistoryStore()

	_ = users.CreateOrUpdate(ctx, &core.User{ID: "ss-user", Email: "user@example.com"})
	clients.AddSeed(&core.Client{
		ID: "ss-app", Secret: "secret", Active: true,
		AllowedAuthenticators: []string{"password"},
		AllowedScopes:         []string{"openid", "profile", "email"},
		TokenStrategy:         "jwt",
	})

	issuer := defaultimpl.NewEd25519JWTIssuer()
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*core.AuthResult, error) {
			return &core.AuthResult{UserID: "ss-user", Provider: "password"}, nil
		},
	))

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithSessionManager(sessions),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDeviceStore(devStore),
		sso.WithLoginHistoryStore(loginHist),
	)

	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()

	// Login to get token
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "ss-app",
		"credential": map[string]string{"username": "ss-user", "password": "any"},
		"scope":      []string{"openid", "profile"},
	})
	loginResp, err := http.Post(hsrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer loginResp.Body.Close()

	var loginResult map[string]any
	json.NewDecoder(loginResp.Body).Decode(&loginResult)
	if loginResp.StatusCode != 200 {
		t.Fatalf("login failed: %v", loginResult["error"])
	}
	token := loginResult["access_token"].(string)

	// Extract device ID from login response
	var deviceID string
	if d := loginResult["device"]; d != nil {
		dm := d.(map[string]any)
		deviceID = dm["id"].(string)
	}
	if deviceID == "" {
		t.Fatal("no device ID in login response")
	}

	t.Run("GetMe", func(t *testing.T) {
		req, _ := http.NewRequest("GET", hsrv.URL+"/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /me: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("GET /me: status=%d", resp.StatusCode)
		}

		var me map[string]any
		json.NewDecoder(resp.Body).Decode(&me)
		if me["sub"] != "ss-user" {
			t.Errorf("expected sub 'ss-user', got '%v'", me["sub"])
		}
		t.Logf("GET /me: sub=%v email=%v", me["sub"], me["email"])
	})

	t.Run("ListDevices", func(t *testing.T) {
		req, _ := http.NewRequest("GET", hsrv.URL+"/me/devices", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /me/devices: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("GET /me/devices: status=%d", resp.StatusCode)
		}

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		if result["devices"] == nil {
			t.Fatal("expected devices array in response")
		}
		devices := result["devices"].([]any)
		if len(devices) != 1 {
			t.Errorf("expected 1 device, got %d", len(devices))
		}
		t.Logf("devices: %d found", len(devices))
	})

	t.Run("GetDeviceByID", func(t *testing.T) {
		req, _ := http.NewRequest("GET", hsrv.URL+"/me/devices/"+deviceID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /me/devices/%s: %v", deviceID, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("GET device: status=%d", resp.StatusCode)
		}

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		if result["id"] != deviceID {
			t.Errorf("expected device id %s, got %v", deviceID, result["id"])
		}
		if result["active_sessions"] == nil {
			t.Error("expected active_sessions in device response")
		}
		t.Logf("device %s: type=%v sessions=%v", deviceID, result["type"], result["active_sessions"])
	})

	t.Run("UpdateDeviceName", func(t *testing.T) {
		updateBody, _ := json.Marshal(map[string]string{
			"device_name": "My Test Machine",
			"notes":       "Integration test device",
		})
		req, _ := http.NewRequest("PATCH", hsrv.URL+"/me/devices/"+deviceID, bytes.NewReader(updateBody))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PATCH device: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		t.Logf("PATCH response: status=%d body=%s", resp.StatusCode, string(raw))
		if resp.StatusCode != 200 {
			t.Fatalf("PATCH device: status=%d body=%s", resp.StatusCode, string(raw))
		}
	})

	t.Run("LoginHistory", func(t *testing.T) {
		req, _ := http.NewRequest("GET", hsrv.URL+"/me/login-history", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET login-history: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("login-history: status=%d", resp.StatusCode)
		}

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		if result["login_history"] == nil {
			t.Fatal("expected login_history array")
		}
		entries := result["login_history"].([]any)
		if len(entries) < 1 {
			t.Errorf("expected at least 1 login history entry, got %d", len(entries))
		} else {
			entry := entries[0].(map[string]any)
			t.Logf("latest login: time=%v provider=%v success=%v",
				entry["time"], entry["provider"], entry["success"])
		}
	})

	t.Run("Sessions", func(t *testing.T) {
		req, _ := http.NewRequest("GET", hsrv.URL+"/me/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /me/sessions: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("sessions: status=%d", resp.StatusCode)
		}
		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		t.Logf("sessions response keys: %v", keysOf(result))
	})
}
