package main

import (
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/config"
)

func TestBuildApp_BackchannelLogoutFlipsDiscovery(t *testing.T) {
	cfg := &config.Config{}
	cfg.BackchannelLogout.Enabled = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	if v, _ := doc["backchannel_logout_supported"].(bool); !v {
		t.Errorf("backchannel_logout_supported = %v want true", doc["backchannel_logout_supported"])
	}
	// SessionManager is wired by default in cmd, so the session-scoped
	// variant should also flip.
	if v, _ := doc["backchannel_logout_session_supported"].(bool); !v {
		t.Errorf("backchannel_logout_session_supported = %v want true", doc["backchannel_logout_session_supported"])
	}
}

func TestBuildApp_BackchannelLogoutDisabledOmitsDiscoveryFlag(t *testing.T) {
	cfg := &config.Config{}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	if v, _ := doc["backchannel_logout_supported"].(bool); v {
		t.Error("backchannel_logout_supported true when not wired")
	}
}
