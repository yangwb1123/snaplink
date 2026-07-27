package main

import (
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
)

// TestBuildConsentStore_DisabledByDefault: an empty backend returns (nil, nil)
// so consent enforcement stays off and the routes stay unmounted.
func TestBuildConsentStore_DisabledByDefault(t *testing.T) {
	t.Parallel()
	s, err := serverbuildstore.BuildConsentStore(config.SelfServiceStoreConfig{}, nil, "")
	if err != nil {
		t.Fatalf("disabled build: %v", err)
	}
	if s != nil {
		t.Fatalf("expected nil store when backend is empty, got %T", s)
	}
}

// TestBuildConsentStore_Memory: memory backend yields a usable store.
func TestBuildConsentStore_Memory(t *testing.T) {
	t.Parallel()
	s, err := serverbuildstore.BuildConsentStore(config.SelfServiceStoreConfig{Backend: "memory"}, nil, "")
	if err != nil {
		t.Fatalf("memory build: %v", err)
	}
	if s == nil {
		t.Fatal("memory store nil")
	}
}

// TestBuildConsentStore_SQLiteNeedsDSN: sqlite backend without a DSN errors.
func TestBuildConsentStore_SQLiteNeedsDSN(t *testing.T) {
	t.Parallel()
	if _, err := serverbuildstore.BuildConsentStore(config.SelfServiceStoreConfig{Backend: "sqlite"}, nil, ""); err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

// TestBuildConsentStore_SQLiteOpensFile: sqlite backend with a DSN opens.
func TestBuildConsentStore_SQLiteOpensFile(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "consent.db") + "?_journal=WAL"
	s, err := serverbuildstore.BuildConsentStore(config.SelfServiceStoreConfig{
		Backend: "sqlite",
		SQLite:  config.IdentitySQLiteConfig{DSN: dsn},
	}, nil, "")
	if err != nil {
		t.Fatalf("sqlite build: %v", err)
	}
	if s == nil {
		t.Fatal("sqlite store nil")
	}
}

// TestBuildConsentStore_UnknownBackend: an unknown backend is a loud error.
func TestBuildConsentStore_UnknownBackend(t *testing.T) {
	t.Parallel()
	if _, err := serverbuildstore.BuildConsentStore(config.SelfServiceStoreConfig{Backend: "bogus"}, nil, ""); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}
