package serverbuildplatform

import (
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/configaudit"
	"github.com/snaplink/sso/shared/core/corecredential"
	"github.com/snaplink/sso/shared/spi"
)

func govLogger() spi.Logger { return spi.NopLogger{} }

func TestBuildCredentialRotation_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	reg, sched, err := BuildCredentialRotation(config.RotationConfig{}, nil, govLogger(), nil)
	if err != nil {
		t.Fatalf("BuildCredentialRotation: %v", err)
	}
	if reg != nil || sched != nil {
		t.Fatalf("disabled rotation must return (nil, nil); got reg=%v sched=%v", reg, sched)
	}
}

func TestBuildCredentialRotation_EnabledRegistersWebhookRotator(t *testing.T) {
	t.Parallel()
	cfg := config.RotationConfig{Enabled: true, Interval: time.Hour, Overlap: time.Minute}
	reg, sched, err := BuildCredentialRotation(cfg, []byte("seed-secret"), govLogger(), nil)
	if err != nil {
		t.Fatalf("BuildCredentialRotation: %v", err)
	}
	if reg == nil || sched == nil {
		t.Fatal("enabled rotation must return a registry + scheduler")
	}
	inv := reg.Inventory()
	if len(inv) != 1 {
		t.Fatalf("inventory = %d entries; want 1 (the webhook rotator)", len(inv))
	}
	if inv[0].Type != corecredential.CredentialTypeWebhookHMAC {
		t.Errorf("inventory type = %q; want %q", inv[0].Type, corecredential.CredentialTypeWebhookHMAC)
	}
}

func TestBuildCredentialRotation_RequiresIntervalWhenEnabled(t *testing.T) {
	t.Parallel()
	cfg := config.RotationConfig{Enabled: true} // Interval left 0
	if _, _, err := BuildCredentialRotation(cfg, nil, govLogger(), nil); err == nil {
		t.Fatal("expected error: rotation.interval required when enabled")
	}
}

func TestBuildConfigAuditStore_MemoryDefault(t *testing.T) {
	t.Parallel()
	for _, backend := range []string{"", "memory", "MEMORY"} {
		store, err := BuildConfigAuditStore(config.ConfigAuditConfig{Backend: backend})
		if err != nil {
			t.Fatalf("backend=%q: %v", backend, err)
		}
		if store == nil {
			t.Fatalf("backend=%q: nil store", backend)
		}
	}
}

func TestBuildConfigAuditStore_Sqlite(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "cfgaudit.db") + "?_journal=WAL"
	store, err := BuildConfigAuditStore(config.ConfigAuditConfig{
		Backend: "sqlite",
		Sqlite:  config.ConfigAuditSqliteConfig{DSN: dsn},
	})
	if err != nil {
		t.Fatalf("BuildConfigAuditStore(sqlite): %v", err)
	}
	c, ok := store.(io.Closer)
	if !ok {
		t.Fatal("sqlite config-audit store must be an io.Closer")
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestBuildConfigAuditStore_SqliteRequiresDSN(t *testing.T) {
	t.Parallel()
	if _, err := BuildConfigAuditStore(config.ConfigAuditConfig{Backend: "sqlite"}); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
}

func TestBuildConfigAuditStore_UnknownBackend(t *testing.T) {
	t.Parallel()
	if _, err := BuildConfigAuditStore(config.ConfigAuditConfig{Backend: "redis"}); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

// TestEffectiveConfigSnapshot_RedactsAndIsDigestible proves the snapshot
// scrubs credential-bearing leaves (so an operator-visible snapshot never
// leaks a secret) AND that the result is stable-digestible — configaudit.Digest
// json-marshals it, so a non-JSON-serializable map would fail there.
func TestEffectiveConfigSnapshot_RedactsAndIsDigestible(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Audit.Webhook.SigningSecret = "top-secret-value"
	cfg.Server.Issuer = "https://sso.example.com"

	snap, err := EffectiveConfigSnapshot(cfg)
	if err != nil {
		t.Fatalf("EffectiveConfigSnapshot: %v", err)
	}
	audit, _ := snap["audit"].(map[string]any)
	webhook, _ := audit["webhook"].(map[string]any)
	if got := webhook["signing_secret"]; got != "***" {
		t.Errorf("signing_secret = %v; want redacted %q", got, "***")
	}
	// A non-sensitive leaf survives verbatim.
	server, _ := snap["server"].(map[string]any)
	if got := server["issuer"]; got != "https://sso.example.com" {
		t.Errorf("issuer = %v; want the configured value (non-sensitive, unredacted)", got)
	}
	if _, err := configaudit.Digest(snap); err != nil {
		t.Fatalf("snapshot must be JSON-digestible: %v", err)
	}
}
