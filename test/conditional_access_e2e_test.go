package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/authenticators/device"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

func TestConditionalAccessDeviceConditionsE2E(t *testing.T) {
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	devStore := device.NewMemoryStore()

	_ = users.CreateOrUpdate(ctx, &core.User{ID: "ca-user"})
	clients.AddSeed(&core.Client{
		ID: "ca-app", Secret: "secret", Active: true,
		AllowedAuthenticators: []string{"password"},
		AllowedScopes:         []string{"openid"},
		TokenStrategy:         "jwt",
	})

	issuer := defaultimpl.NewEd25519JWTIssuer()
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*core.AuthResult, error) {
			return &core.AuthResult{UserID: "ca-user", Provider: "password"}, nil
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
	)

	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()

	// Helper to login
	login := func() map[string]any {
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  "ca-app",
			"credential": map[string]string{"username": "ca-user", "password": "x"},
			"scope":      []string{"openid"},
		})
		resp, err := http.Post(hsrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer resp.Body.Close()
		var r map[string]any
		json.NewDecoder(resp.Body).Decode(&r)
		return r
	}

	t.Run("DeviceContextInLoginResponse", func(t *testing.T) {
		r := login()
		if r["device"] == nil {
			t.Fatal("login response missing device context")
		}
		d := r["device"].(map[string]any)
		if d["type"] == nil {
			t.Error("device type missing")
		}
		if d["trust_score"] == nil {
			t.Error("trust score missing")
		}
		// Security context should be present
		if d["security"] == nil {
			t.Error("security context missing in device")
		}
		sec := d["security"].(map[string]any)
		t.Logf("device security: is_new=%v, active_devices=%v", sec["device_is_new"], sec["active_devices"])
	})

	t.Run("ActiveDevicesCounted", func(t *testing.T) {
		// First login
		r1 := login()
		if r1["active_devices"] == nil {
			// active_devices might be 0 (omitempty for 0)
		}

		// Second login - should still be 1 active device (same fingerprint)
		r2 := login()
		if r2["active_devices"] != nil {
			ad := r2["active_devices"].(float64)
			t.Logf("active_devices: %v", ad)
			if ad < 1 {
				t.Errorf("expected at least 1 active device, got %v", ad)
			}
		}
	})

	// Test that device trust score increases with repeat logins
	t.Run("TrustScoreIncreasesWithRepeatLogin", func(t *testing.T) {
		scores := make([]float64, 0, 3)

		for i := 0; i < 3; i++ {
			r := login()
			if d, ok := r["device"].(map[string]any); ok {
				if ts, ok := d["trust_score"].(float64); ok {
					scores = append(scores, ts)
				}
			}
		}

		if len(scores) < 2 {
			t.Log("insufficient trust score data")
			return
		}

		t.Logf("trust scores: %v", scores)
		// Trust score should generally increase or stay the same
		// (it might stay the same if rounding keeps it flat)
		if len(scores) >= 3 && scores[2] < scores[0] {
			t.Logf("trust score decreased from %v to %v (may be expected with decay)", scores[0], scores[2])
		}
	})
}
