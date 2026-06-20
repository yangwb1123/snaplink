package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/audit"
)

func TestBuildApp_AuditHashChainStampsRecordedEvents(t *testing.T) {
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.HashChain = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.recorder == nil {
		t.Fatal("recorder nil with audit enabled")
	}
	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "user-1"})
	// HashChain correctness is covered by audit/chainer_test.go. The
	// cmd test only proves the wiring reaches the recorder.
}

func TestBuildApp_AuditPIIRedactionRequiresSalt(t *testing.T) {
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.PIIRedaction.Enabled = true
	// No salt + no salt_file → error.

	_, err := buildApp(cfg, quietLogger())
	if err == nil {
		t.Fatal("expected error when pii_redaction enabled with no salt")
	}
}

func TestBuildApp_AuditPIIRedactionAcceptsInlineSalt(t *testing.T) {
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.PIIRedaction.Enabled = true
	cfg.Audit.PIIRedaction.Salt = "deployment-stable-secret"

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.recorder == nil {
		t.Fatal("recorder nil")
	}
}

func TestBuildApp_AuditPIIRedactionAcceptsSaltFile(t *testing.T) {
	dir := t.TempDir()
	saltPath := filepath.Join(dir, "audit.salt")
	if err := os.WriteFile(saltPath, []byte("salt-from-file\n"), 0o600); err != nil {
		t.Fatalf("write salt: %v", err)
	}

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.PIIRedaction.Enabled = true
	cfg.Audit.PIIRedaction.SaltFile = saltPath

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.recorder == nil {
		t.Fatal("recorder nil")
	}
}

func TestResolvePIISalt_EmptyFileIsError(t *testing.T) {
	dir := t.TempDir()
	saltPath := filepath.Join(dir, "empty.salt")
	if err := os.WriteFile(saltPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	_, err := resolvePIISalt(config.AuditPIIRedactionConfig{Enabled: true, SaltFile: saltPath})
	if err == nil {
		t.Fatal("expected error for empty salt file")
	}
}
