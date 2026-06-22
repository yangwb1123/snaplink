package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"github.com/snaplink/sso/config"
)

func TestBuildAuthCodeStore_MemoryDefault(t *testing.T) {
	s, err := serverbuildstore.BuildAuthCodeStore(config.OAuthConfig{}, nil)
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
}

func TestBuildAuthCodeStore_SQLiteNeedsDSN(t *testing.T) {
	_, err := serverbuildstore.BuildAuthCodeStore(config.OAuthConfig{Backend: "sqlite"}, nil)
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildAuthCodeStore_SQLiteOpensFile(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "auth.db") + "?_journal=WAL"
	s, err := serverbuildstore.BuildAuthCodeStore(config.OAuthConfig{
		Backend: "sqlite",
		SQLite:  config.OAuthSQLiteConfig{DSN: dsn},
	}, nil)
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
}

func TestBuildRefreshTokenStore_SQLiteOpensFile(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "refresh.db") + "?_journal=WAL"
	s, err := serverbuildstore.BuildRefreshTokenStore(config.OAuthConfig{
		Backend: "sqlite",
		SQLite:  config.OAuthSQLiteConfig{DSN: dsn},
	}, nil)
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
}

func TestBuildDeviceCodeStore_UnknownBackendErrors(t *testing.T) {
	_, err := serverbuildstore.BuildDeviceCodeStore(config.OAuthConfig{Backend: "redis"}, nil)
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildPARStore_MemoryDefault(t *testing.T) {
	s, err := serverbuildstore.BuildPARStore(config.OAuthConfig{}, nil)
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
}

func TestBuildPARStore_SQLiteNeedsDSN(t *testing.T) {
	_, err := serverbuildstore.BuildPARStore(config.OAuthConfig{Backend: "sqlite"}, nil)
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildPARStore_SQLiteOpensFile(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "par.db") + "?_journal=WAL"
	s, err := serverbuildstore.BuildPARStore(config.OAuthConfig{
		Backend: "sqlite",
		SQLite:  config.OAuthSQLiteConfig{DSN: dsn},
	}, nil)
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
}

func TestBuildPARStore_UnknownBackendErrors(t *testing.T) {
	_, err := serverbuildstore.BuildPARStore(config.OAuthConfig{Backend: "redis"}, nil)
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildClientStore_MemoryDefault(t *testing.T) {
	s, err := serverbuildstore.BuildClientStore(config.IdentityConfig{}, nil, "")
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
}

func TestBuildClientStore_SQLiteNeedsDSN(t *testing.T) {
	_, err := serverbuildstore.BuildClientStore(config.IdentityConfig{Backend: "sqlite"}, nil, "")
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildSessionManager_MemoryDefault(t *testing.T) {
	m, err := serverbuildstore.BuildSessionManager(config.IdentityConfig{}, time.Hour, nil)
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if m == nil {
		t.Fatal("session manager nil")
	}
}

func TestBuildSessionManager_SQLiteNeedsDSN(t *testing.T) {
	_, err := serverbuildstore.BuildSessionManager(config.IdentityConfig{Backend: "sqlite"}, time.Hour, nil)
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildSessionManager_SQLiteOpensFile(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "sessions.db") + "?_journal=WAL"
	m, err := serverbuildstore.BuildSessionManager(config.IdentityConfig{
		Backend: "sqlite",
		SQLite:  config.IdentitySQLiteConfig{DSN: dsn},
	}, time.Hour, nil)
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if m == nil {
		t.Fatal("session manager nil")
	}
}

func TestBuildApp_IdentitySQLiteEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "identity.db") + "?_journal=WAL"

	cfg := &config.Config{}
	cfg.Identity.Backend = "sqlite"
	cfg.Identity.SQLite.DSN = dsn

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.clientStore == nil || a.userProvider == nil {
		t.Fatal("identity stores not wired")
	}
}

func TestBuildApp_SQLiteEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "sso.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"

	cfg := &config.Config{}
	cfg.OAuth.Backend = "sqlite"
	cfg.OAuth.SQLite.DSN = dsn
	cfg.OAuth.AuthCode.Enabled = true
	cfg.OAuth.RefreshToken.Enabled = true
	cfg.OAuth.DeviceCode.Enabled = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.server == nil {
		t.Fatal("server nil")
	}
}
