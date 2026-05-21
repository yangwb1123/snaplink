package main

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
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

func TestBuildSubjectClientIndex_MemoryDefault(t *testing.T) {
	idx, mode, err := buildSubjectClientIndex(config.BCLIndexConfig{})
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if idx == nil {
		t.Fatal("index nil")
	}
	if !strings.Contains(mode, "memory") {
		t.Fatalf("mode label %q missing memory marker", mode)
	}
}

func TestBuildSubjectClientIndex_SQLiteNeedsDSN(t *testing.T) {
	_, _, err := buildSubjectClientIndex(config.BCLIndexConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildSubjectClientIndex_SQLiteOpensFile(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "sci.db") + "?_journal=WAL"
	idx, mode, err := buildSubjectClientIndex(config.BCLIndexConfig{
		Backend: "sqlite",
		SQLite:  config.BCLIndexSQLiteConfig{DSN: dsn},
	})
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if idx == nil {
		t.Fatal("index nil")
	}
	if !strings.Contains(mode, "sqlite") {
		t.Fatalf("mode label %q missing sqlite marker", mode)
	}
}

func TestBuildSubjectClientIndex_UnknownBackendErrors(t *testing.T) {
	_, _, err := buildSubjectClientIndex(config.BCLIndexConfig{Backend: "etcd"})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildApp_BCL_SQLiteIndexWires(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "bcl.db") + "?_journal=WAL"
	cfg := &config.Config{}
	cfg.BackchannelLogout.Enabled = true
	cfg.BackchannelLogout.Index.Backend = "sqlite"
	cfg.BackchannelLogout.Index.SQLite.DSN = dsn

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	if v, _ := doc["backchannel_logout_supported"].(bool); !v {
		t.Errorf("backchannel_logout_supported false despite sqlite index")
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
