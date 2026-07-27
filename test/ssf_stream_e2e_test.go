package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestSSFConfigurationAndStreamStoreE2E(t *testing.T) {
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	streamStore := caep.NewMemoryStreamStore()

	_ = users.CreateOrUpdate(ctx, &core.User{ID: "ssf-user"})
	clients.AddSeed(&core.Client{
		ID: "ssf-client", Secret: "secret", Active: true,
		TokenStrategy: "jwt",
	})

	issuer := defaultimpl.NewEd25519JWTIssuer()
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*core.AuthResult, error) {
			return &core.AuthResult{UserID: "ssf-user", Provider: "password"}, nil
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
		sso.WithCAEPStreamStore(streamStore),
	)

	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()

	// --- Test SSF configuration endpoint ---
	t.Run("SSFConfiguration", func(t *testing.T) {
		resp, err := http.Get(hsrv.URL + "/.well-known/ssf-configuration")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var doc map[string]any
		json.NewDecoder(resp.Body).Decode(&doc)
		if doc["issuer"] != "https://sso.test" {
			t.Errorf("issuer: expected 'https://sso.test', got '%v'", doc["issuer"])
		}
		if doc["delivery_methods_supported"] == nil {
			t.Error("delivery_methods_supported is required")
		}
		t.Logf("SSF config OK: issuer=%v delivery=%v", doc["issuer"], doc["delivery_methods_supported"])
	})

	// --- Test Stream Store through server accessor ---
	t.Run("StreamStoreIntegration", func(t *testing.T) {
		s := &caep.Stream{
			Issuer:  "https://sso.test",
			Subject: "user:alice",
			Events:  []string{"https://schemas.openid.net/secevent/caep/token-revocation"},
			Delivery: &caep.StreamDelivery{
				Method:   "https://schemas.openid.net/secevent/ssf/delivery-method/push",
				Endpoint: "https://rp.example.com/ssf",
			},
		}
		if err := streamStore.Create(ctx, s); err != nil {
			t.Fatalf("create stream: %v", err)
		}
		if s.ID == "" {
			t.Fatal("auto-generated ID expected")
		}

		got, err := streamStore.Get(ctx, s.ID)
		if err != nil {
			t.Fatalf("get stream: %v", err)
		}
		if got.Issuer != "https://sso.test" {
			t.Errorf("issuer: %s", got.Issuer)
		}

		streams, err := streamStore.List(ctx, "")
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(streams) != 1 {
			t.Errorf("expected 1 stream, got %d", len(streams))
		}

		if err := streamStore.Delete(ctx, s.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}

		_, err = streamStore.Get(ctx, s.ID)
		if err == nil {
			t.Error("expected error after deletion")
		}
		t.Log("Stream store CRUD OK")
	})

	// --- Test auth/login works with SSF store wired ---
	t.Run("LoginWithSSFStoreWorks", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  "ssf-client",
			"credential": map[string]string{"username": "ssf-user", "password": "x"},
		})
		resp, err := http.Post(hsrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			var result map[string]any
			json.NewDecoder(resp.Body).Decode(&result)
			t.Fatalf("login: status=%d error=%v", resp.StatusCode, result["error"])
		}
		t.Log("Login with SSF store works")
	})
}
