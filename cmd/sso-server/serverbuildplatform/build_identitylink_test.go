package serverbuildplatform

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

func TestBuildIdentityLinkDurableSQLite(t *testing.T) {
	cfg := config.IdentityLinkConfig{
		Enabled: true,
		Backend: "sqlite",
		SQLite:  config.IdentitySQLiteConfig{DSN: filepath.Join(t.TempDir(), "links.db")},
	}
	store, policy, err := BuildIdentityLinkDurable(cfg, nil, "")
	if err != nil {
		t.Fatalf("BuildIdentityLinkDurable: %v", err)
	}
	if policy != nil {
		t.Fatalf("default policy = %v, want nil", policy)
	}
	if _, err := store.Link(context.Background(), "user", "provider", "subject"); err != nil {
		t.Fatalf("durable Link: %v", err)
	}
	if closer, ok := store.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func TestBuildIdentityLinkDurableRejectsMissingDependencies(t *testing.T) {
	for _, cfg := range []config.IdentityLinkConfig{
		{Enabled: true, Backend: "sqlite"},
		{Enabled: true, Backend: "postgres"},
		{Enabled: true, Backend: "unknown"},
	} {
		if _, _, err := BuildIdentityLinkDurable(cfg, nil, ""); err == nil {
			t.Fatalf("config %+v unexpectedly succeeded", cfg)
		}
	}
}
