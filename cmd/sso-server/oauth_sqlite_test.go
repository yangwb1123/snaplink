package main

import (
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/config"
)

func TestBuildAuthCodeStore_MemoryDefault(t *testing.T) {
	s, err := buildAuthCodeStore(config.OAuthConfig{})
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
}

func TestBuildAuthCodeStore_SQLiteNeedsDSN(t *testing.T) {
	_, err := buildAuthCodeStore(config.OAuthConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildAuthCodeStore_SQLiteOpensFile(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "auth.db") + "?_journal=WAL"
	s, err := buildAuthCodeStore(config.OAuthConfig{
		Backend: "sqlite",
		SQLite:  config.OAuthSQLiteConfig{DSN: dsn},
	})
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
	s, err := buildRefreshTokenStore(config.OAuthConfig{
		Backend: "sqlite",
		SQLite:  config.OAuthSQLiteConfig{DSN: dsn},
	})
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
}

func TestBuildDeviceCodeStore_UnknownBackendErrors(t *testing.T) {
	_, err := buildDeviceCodeStore(config.OAuthConfig{Backend: "redis"})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuildClientStore_MemoryDefault(t *testing.T) {
	s, err := buildClientStore(config.IdentityConfig{})
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("store nil")
	}
}

func TestBuildClientStore_SQLiteNeedsDSN(t *testing.T) {
	_, err := buildClientStore(config.IdentityConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
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
	defer a.registry.Close()
	if a.clientStore == nil || a.userProvider == nil {
		t.Fatal("identity stores not wired")
	}
}

func TestBuildApp_SQLiteEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "sso.db") + "?_journal=WAL&_busy_timeout=5000"

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
	defer a.registry.Close()
	if a.server == nil {
		t.Fatal("server nil")
	}
}
