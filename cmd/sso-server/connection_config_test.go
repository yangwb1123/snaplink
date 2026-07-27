package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	cfg := &config.Config{Connections: config.ConnectionsConfig{Enabled: true, Backend: "sqlite"}}
	if _, err := serverbuildstore.BuildConnectionStore(cfg, quietLogger()); err == nil {
		t.Error("sqlite backend without dsn must error")
	}
}

func TestBuildConnectionStore_UnknownBackend(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// TestBuildApp_ConnectionsProbeTimeoutWired proves connections.probe.timeout
// actually reaches the wired sso.Server (via sso.WithConnectionProbeTimeout in
// wireConnectionsAndCache), not just parsed and dropped. A listener that
// accepts but never responds would hang for the connections.DefaultProbeTimeout
// (10s) default; with a 100ms configured timeout the admin probe endpoint must
// come back well under that, marking the connection unreachable.
func TestBuildApp_ConnectionsProbeTimeoutWired(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and hold the connection open without ever writing a
			// response — simulates a hung upstream so the probe can only
			// return via ITS OWN timeout, not a fast connection-refused.
			go func() { <-make(chan struct{}); _ = c.Close() }()
		}
	}()

	cfg := &config.Config{}
	cfg.Connections = config.ConnectionsConfig{
		Enabled: true, Backend: "memory",
		Probe: config.ConnectionsProbeConfig{Timeout: 100 * time.Millisecond},
		Connections: []config.ConnectionSeedConfig{{
			ID: "hung", TenantID: "t1", Type: "oidc", Enabled: true,
			Config: map[string]string{"oidc_issuer": "http://" + ln.Addr().String()},
		}},
	}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	start := time.Now()
	resp, err := http.Post(srv.URL+"/api/v1/admin/connections/hung/probe", "application/json", nil)
	if err != nil {
		t.Fatalf("POST probe: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	elapsed := time.Since(start)
	// Generous upper bound: well past 100ms, well short of the 10s default —
	// proves the CONFIGURED timeout governed the round-trip, not the default.
	if elapsed > 5*time.Second {
		t.Errorf("probe took %v, want well under the 10s default (timeout not wired?)", elapsed)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("probe status=%d, want 200", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["status"] != "unreachable" {
		t.Errorf("probe result = %v, want status=unreachable", out)
	}
}
