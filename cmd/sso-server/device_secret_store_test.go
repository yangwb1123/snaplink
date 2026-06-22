package main

import (
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"github.com/snaplink/sso/config"
)

func TestBuildDeviceSecretStore_DisabledByDefault(t *testing.T) {
	s, err := serverbuildstore.BuildDeviceSecretStore(config.NativeSSOConfig{}, nil, "")
	if err != nil {
		t.Fatalf("disabled build: %v", err)
	}
	if s != nil {
		t.Fatalf("expected nil store when backend empty, got %T", s)
	}
}

func TestBuildDeviceSecretStore_Memory(t *testing.T) {
	s, err := serverbuildstore.BuildDeviceSecretStore(config.NativeSSOConfig{Backend: "memory"}, nil, "")
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("memory store nil")
	}
}

func TestBuildDeviceSecretStore_SQLiteNeedsDSN(t *testing.T) {
	if _, err := serverbuildstore.BuildDeviceSecretStore(config.NativeSSOConfig{Backend: "sqlite"}, nil, ""); err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildDeviceSecretStore_SQLiteOpensFile(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "ds.db") + "?_journal=WAL"
	s, err := serverbuildstore.BuildDeviceSecretStore(config.NativeSSOConfig{Backend: "sqlite", SQLite: config.IdentitySQLiteConfig{DSN: dsn}}, nil, "")
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if s == nil {
		t.Fatal("sqlite store nil")
	}
}

func TestBuildDeviceSecretStore_UnknownBackend(t *testing.T) {
	if _, err := serverbuildstore.BuildDeviceSecretStore(config.NativeSSOConfig{Backend: "bogus"}, nil, ""); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}
