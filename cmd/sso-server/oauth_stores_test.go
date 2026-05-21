package main

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
)

func TestBuildApp_AllOAuthStoresEnabled_BuildsCleanly(t *testing.T) {
	cfg := &config.Config{}
	cfg.OAuth.AuthCode = config.OAuthStoreConfig{Enabled: true, TTL: 10 * time.Minute}
	cfg.OAuth.RefreshToken = config.OAuthStoreConfig{Enabled: true, TTL: 30 * 24 * time.Hour}
	cfg.OAuth.DeviceCode = config.OAuthDeviceCodeConfig{
		Enabled:             true,
		TTL:                 10 * time.Minute,
		PollInterval:        5 * time.Second,
		VerificationBaseURL: "https://example.com/device",
	}
	cfg.OAuth.PAR = config.OAuthStoreConfig{Enabled: true, TTL: 90 * time.Second}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	if a.server == nil {
		t.Fatal("server is nil after buildApp")
	}
}

func TestBuildApp_PARStoreEnabledAdvertisesEndpoint(t *testing.T) {
	cfg := &config.Config{}
	cfg.OAuth.PAR = config.OAuthStoreConfig{Enabled: true}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	endpoint, _ := doc["pushed_authorization_request_endpoint"].(string)
	if endpoint == "" {
		t.Errorf("pushed_authorization_request_endpoint missing — PARStore wiring broken")
	}
}

func TestBuildApp_PARStoreDisabledOmitsEndpoint(t *testing.T) {
	cfg := &config.Config{}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	if _, present := doc["pushed_authorization_request_endpoint"]; present {
		t.Error("PAR endpoint advertised when not enabled — omitempty broken")
	}
}
