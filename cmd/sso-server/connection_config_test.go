package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"github.com/snaplink/sso/config"
)

func acmeConnectionsConfig() config.ConnectionsConfig {
	return config.ConnectionsConfig{
		Enabled: true,
		Backend: "memory",
		Connections: []config.ConnectionSeedConfig{{
			ID:          "acme",
			TenantID:    "t-acme",
			Type:        "oidc",
			DisplayName: "Acme Corp",
			Domains:     []string{"acme.com"},
			Enabled:     true,
			Config:      map[string]string{"oidc_issuer": "https://idp.acme.com"},
		}},
	}
}

func TestBuildConnectionStore_SeedsAndResolves(t *testing.T) {
	cfg := &config.Config{Connections: acmeConnectionsConfig()}
	store, err := serverbuildstore.BuildConnectionStore(cfg, quietLogger())
	if err != nil {
		t.Fatalf("serverbuildstore.BuildConnectionStore: %v", err)
	}
	if store == nil {
		t.Fatal("store is nil when connections enabled")
	}
	conn, err := store.ByDomain(context.Background(), "acme.com")
	if err != nil {
		t.Fatalf("ByDomain(acme.com): %v", err)
	}
	if conn.ID != "acme" || conn.DisplayName != "Acme Corp" || string(conn.Type) != "oidc" {
		t.Errorf("resolved connection = %+v", conn)
	}
	// A domain with no connection misses.
	if _, err := store.ByDomain(context.Background(), "other.com"); err == nil {
		t.Error("unmatched domain must miss")
	}
}

func TestBuildConnectionStore_DisabledIsNil(t *testing.T) {
	cfg := &config.Config{}
	store, err := serverbuildstore.BuildConnectionStore(cfg, quietLogger())
	if err != nil {
		t.Fatalf("serverbuildstore.BuildConnectionStore: %v", err)
	}
	if store != nil {
		t.Error("store must be nil when connections disabled")
	}
}

func TestBuildConnectionStore_SQLiteRequiresDSN(t *testing.T) {
	cfg := &config.Config{Connections: config.ConnectionsConfig{Enabled: true, Backend: "sqlite"}}
	if _, err := serverbuildstore.BuildConnectionStore(cfg, quietLogger()); err == nil {
		t.Error("sqlite backend without dsn must error")
	}
}

func TestBuildConnectionStore_UnknownBackend(t *testing.T) {
	cfg := &config.Config{Connections: config.ConnectionsConfig{Enabled: true, Backend: "redis"}}
	if _, err := serverbuildstore.BuildConnectionStore(cfg, quietLogger()); err == nil {
		t.Error("unknown backend must error")
	}
}

// TestBuildApp_ConnectionsMountsHomeRealm proves the full wiring: a seeded
// connection is reachable through the /auth/home-realm endpoint after buildApp,
// so the B2B home-realm feature is operable from the binary (previously the
// store could only be populated by SDK embedders).
func TestBuildApp_ConnectionsMountsHomeRealm(t *testing.T) {
	cfg := &config.Config{}
	cfg.Connections = acmeConnectionsConfig()

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if c, ok := a.connectionStore.(io.Closer); ok {
		defer func() { _ = c.Close() }()
	}

	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/auth/home-realm?login_hint=" + "user%40acme.com")
	if err != nil {
		t.Fatalf("GET /auth/home-realm: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if found, _ := out["found"].(bool); !found {
		t.Fatalf("home-realm did not resolve seeded connection: %s", body)
	}
	if out["connection_id"] != "acme" || out["display_name"] != "Acme Corp" {
		t.Errorf("home-realm response = %v", out)
	}

	// An unknown domain falls back to {found:false} — a routing decision, not an oracle.
	resp2, _ := http.Get(srv.URL + "/auth/home-realm?login_hint=" + "user%40nope.com")
	defer func() { _ = resp2.Body.Close() }()
	var out2 map[string]any
	b2, _ := io.ReadAll(resp2.Body)
	_ = json.Unmarshal(b2, &out2)
	if found, _ := out2["found"].(bool); found {
		t.Errorf("unknown domain must not resolve: %s", b2)
	}
}
