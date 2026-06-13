package main

import (
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/config"
)

func TestBuildApp_DCREnabledAdvertisesRegistrationEndpoint(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClientRegistration.Enabled = true
	cfg.ClientRegistration.InitialAccessToken = "operator-distributed-token"

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	endpoint, _ := doc["registration_endpoint"].(string)
	if endpoint == "" {
		t.Errorf("registration_endpoint missing — DCR wiring broken")
	}
}

func TestBuildApp_DCRDisabledOmitsRegistrationEndpoint(t *testing.T) {
	cfg := &config.Config{}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	if _, present := doc["registration_endpoint"]; present {
		t.Error("registration_endpoint advertised when DCR not enabled")
	}
}
