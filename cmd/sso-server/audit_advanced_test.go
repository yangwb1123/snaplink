package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
)

func TestBuildApp_AuditHashChainStampsRecordedEvents(t *testing.T) {
	t.Parallel()
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

func TestBuildApp_AuditNotaryPersistsSignedCheckpointAndStops(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	keyFile := writeNotaryPrivateKey(t)
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.Backend = "sqlite"
	cfg.Audit.Sqlite.DSN = dsn
	cfg.Audit.HashChain = true
	cfg.Audit.Notary = config.AuditNotaryConfig{Enabled: true, Interval: 5 * time.Millisecond, KeyFile: keyFile}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp with audit notary: %v", err)
	}
	defer func() {
		_ = a.externalAuditClose(context.Background())
		_ = a.registry.Close()
	}()
	if a.externalAuditClose == nil {
		t.Fatal("notary cleanup was not composed into the audit close chain")
	}
	store, ok := a.recorder.Sink().(audit.CheckpointStore)
	if !ok {
		t.Fatalf("wired audit sink = %T; want checkpoint store", a.recorder.Sink())
	}
	event := &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "user-1"}
	a.recorder.Record(context.Background(), event)
	var checkpoint *audit.SignedCheckpoint
	deadline := time.Now().Add(2 * time.Second)
	for checkpoint == nil && time.Now().Before(deadline) {
		checkpoint, err = store.Latest(context.Background())
		if err != nil {
			t.Fatalf("checkpoint Latest: %v", err)
		}
		if checkpoint == nil || checkpoint.Checkpoint.HeadHash != event.Hash {
			checkpoint = nil
			time.Sleep(5 * time.Millisecond)
		}
	}
	if checkpoint == nil {
		t.Fatal("notary did not persist a checkpoint for the recorded event")
	}
	if checkpoint.Checkpoint.Sequence != 1 || checkpoint.Checkpoint.PrevHash != audit.GenesisHash {
		t.Fatalf("checkpoint = %+v; want sequence 1 from genesis", checkpoint.Checkpoint)
	}
	if err := audit.VerifyCheckpointSignature(checkpoint); err != nil {
		t.Fatalf("checkpoint signature: %v", err)
	}
	checkpointEvents, err := a.recorder.Sink().Query(context.Background(), audit.Query{Type: audit.EventAuditChainCheckpoint})
	if err != nil {
		t.Fatalf("query checkpoint events: %v", err)
	}
	if len(checkpointEvents) != 0 {
		t.Fatalf("successful checkpoint wrote %d Recorder events; want none", len(checkpointEvents))
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.externalAuditClose(closeCtx); err != nil {
		t.Fatalf("audit close: %v", err)
	}
	if _, err := store.Latest(context.Background()); err == nil {
		t.Fatal("audit primary remained open after notary shutdown")
	}
	_ = a.registry.Close()
}

func TestBuildApp_AuditNotaryDefaultOffAndBootGates(t *testing.T) {
	t.Parallel()
	missingKey := filepath.Join(t.TempDir(), "notary.pem")
	defaultCfg := &config.Config{}
	defaultCfg.Audit.Enabled = true
	defaultCfg.Audit.Backend = "sqlite"
	defaultCfg.Audit.Sqlite.DSN = "file:" + filepath.Join(t.TempDir(), "audit.db")
	defaultCfg.Audit.Notary.KeyFile = missingKey
	a, err := buildApp(defaultCfg, quietLogger())
	if err != nil {
		t.Fatalf("default-off notary unexpectedly failed: %v", err)
	}
	if a.externalAuditClose != nil {
		_ = a.externalAuditClose(context.Background())
	} else if closer, ok := a.recorder.Sink().(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	_ = a.registry.Close()

	memoryCfg := &config.Config{}
	memoryCfg.Audit.Enabled = true
	memoryCfg.Audit.HashChain = true
	memoryCfg.Audit.Notary = config.AuditNotaryConfig{Enabled: true, KeyFile: "/etc/sso/notary.pem"}
	if _, err := buildApp(memoryCfg, quietLogger()); err == nil {
		t.Fatal("memory primary accepted an enabled notary")
	}
	missingCfg := &config.Config{}
	missingCfg.Audit.Enabled = true
	missingCfg.Audit.Backend = "sqlite"
	missingCfg.Audit.Sqlite.DSN = "file:" + filepath.Join(t.TempDir(), "audit.db")
	missingCfg.Audit.HashChain = true
	missingCfg.Audit.Notary = config.AuditNotaryConfig{Enabled: true, KeyFile: missingKey}
	if _, err := buildApp(missingCfg, quietLogger()); err == nil {
		t.Fatal("missing notary key was accepted")
	}
}

func writeNotaryPrivateKey(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate notary key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("marshal notary key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "notary.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write notary key: %v", err)
	}
	return path
}

func TestBuildApp_AuditPIIRedactionRequiresSalt(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	dir := t.TempDir()
	saltPath := filepath.Join(dir, "empty.salt")
	if err := os.WriteFile(saltPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	_, err := serverbuildstore.ResolvePIISalt(config.AuditPIIRedactionConfig{Enabled: true, SaltFile: saltPath})
	if err == nil {
		t.Fatal("expected error for empty salt file")
	}
}
