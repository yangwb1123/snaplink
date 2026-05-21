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

func TestBuildApp_OAuth21StrictModeFlipsDiscovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.OAuth21StrictMode = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v want [S256] (plain disallowed in 2.1 strict)", methods)
	}
}

func TestBuildApp_JARFetcherFlipsRequestURIParameterSupported(t *testing.T) {
	cfg := &config.Config{}
	cfg.OAuth.JAR = config.OAuthJARConfig{Enabled: true}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	if v, _ := doc["request_uri_parameter_supported"].(bool); !v {
		t.Errorf("request_uri_parameter_supported = %v want true when JAR fetcher wired", doc["request_uri_parameter_supported"])
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
