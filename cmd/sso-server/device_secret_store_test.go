package main

import (
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/config"
)

func TestBuildDeviceSecretStore_DisabledByDefault(t *testing.T) {
	s, err := buildDeviceSecretStore(config.NativeSSOConfig{})
	if err != nil {
		t.Fatalf("disabled build: %v", err)
	}
	if s != nil {
		t.Fatalf("expected nil store when backend empty, got %T", s)
	}
}

func TestBuildDeviceSecretStore_Memory(t *testing.T) {
	s, err := buildDeviceSecretStore(config.NativeSSOConfig{Backend: "memory"})
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("memory store nil")
	}
}

func TestBuildDeviceSecretStore_SQLiteNeedsDSN(t *testing.T) {
	if _, err := buildDeviceSecretStore(config.NativeSSOConfig{Backend: "sqlite"}); err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildDeviceSecretStore_SQLiteOpensFile(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "ds.db") + "?_journal=WAL"
	s, err := buildDeviceSecretStore(config.NativeSSOConfig{Backend: "sqlite", SQLite: config.IdentitySQLiteConfig{DSN: dsn}})
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if s == nil {
		t.Fatal("sqlite store nil")
	}
}

func TestBuildDeviceSecretStore_UnknownBackend(t *testing.T) {
	if _, err := buildDeviceSecretStore(config.NativeSSOConfig{Backend: "bogus"}); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}
