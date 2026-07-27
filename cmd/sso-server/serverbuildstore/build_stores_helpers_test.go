package serverbuildstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

// These unexported helpers back BuildMFA / BuildSnapshotSubsystem /
// BuildTenantStore, but are otherwise unreachable from the root cmd
// package's black-box tests (an unexported identifier can only be called
// from inside this package) — a regression in one of these branches would
// only be pinpointed here, not by any *_test.go in cmd/sso-server itself.

func TestBuildMFAChallengeStore_MemorySqliteRedisUnknown(t *testing.T) {
	t.Parallel()
	s, mode, err := buildMFAChallengeStore(config.MFAChallengeConfig{}, nil)
	if err != nil || s == nil || mode == "" {
		t.Fatalf("memory: store=%v mode=%q err=%v", s, mode, err)
	}

	if _, _, err := buildMFAChallengeStore(config.MFAChallengeConfig{Backend: "sqlite"}, nil); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
	dsn := "file:" + filepath.Join(t.TempDir(), "mfa.db") + "?_journal=WAL"
	s, mode, err = buildMFAChallengeStore(config.MFAChallengeConfig{
		Backend: "sqlite",
		SQLite:  config.MFAChallengeSQLiteConfig{DSN: dsn},
	}, nil)
	if err != nil || s == nil || mode == "" {
		t.Fatalf("sqlite: store=%v mode=%q err=%v", s, mode, err)
	}

	if _, _, err := buildMFAChallengeStore(config.MFAChallengeConfig{Backend: "redis"}, nil); err == nil {
		t.Fatal("expected error: redis backend without a redis client")
	}
	if _, _, err := buildMFAChallengeStore(config.MFAChallengeConfig{Backend: "carrier-pigeon"}, nil); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildPushApprovalStore_MemorySqliteUnknown(t *testing.T) {
	t.Parallel()
	store, sqliteStore, err := buildPushApprovalStore(config.MFAPushConfig{})
	if err != nil || store == nil || sqliteStore != nil {
		t.Fatalf("memory: store=%v sqliteStore=%v err=%v, want (non-nil, nil, nil)", store, sqliteStore, err)
	}

	if _, _, err := buildPushApprovalStore(config.MFAPushConfig{Backend: "sqlite"}); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
	dsn := "file:" + filepath.Join(t.TempDir(), "push.db") + "?_journal=WAL"
	store, sqliteStore, err = buildPushApprovalStore(config.MFAPushConfig{
		Backend: "sqlite",
		SQLite:  config.MFAPushSQLiteConfig{DSN: dsn},
	})
	if err != nil || store == nil || sqliteStore == nil {
		t.Fatalf("sqlite: store=%v sqliteStore=%v err=%v, want both non-nil (readyz + prune wiring needs the typed handle)", store, sqliteStore, err)
	}

	if _, _, err := buildPushApprovalStore(config.MFAPushConfig{Backend: "carrier-pigeon"}); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildPushTransport_LogDefaultDelivers(t *testing.T) {
	t.Parallel()
	for _, transport := range []string{"", "log"} {
		tr, err := buildPushTransport(config.MFAPushConfig{Transport: transport}, testLogger())
		if err != nil || tr == nil {
			t.Fatalf("transport=%q: tr=%v err=%v", transport, tr, err)
		}
		if err := tr.Send(context.Background(), "approval-1", "subject-1", nil); err != nil {
			t.Errorf("transport=%q: Send: %v", transport, err)
		}
	}
}

func TestBuildPushTransport_WebhookRequiresURLAndUnknownErrors(t *testing.T) {
	t.Parallel()
	if _, err := buildPushTransport(config.MFAPushConfig{Transport: "webhook"}, testLogger()); err == nil {
		t.Fatal("expected error: webhook transport requires a url")
	}
	tr, err := buildPushTransport(config.MFAPushConfig{
		Transport: "webhook",
		Webhook:   config.MFAPushWebhookConfig{URL: "https://push.example.com/hook"},
	}, testLogger())
	if err != nil || tr == nil {
		t.Fatalf("webhook: tr=%v err=%v", tr, err)
	}
	if _, err := buildPushTransport(config.MFAPushConfig{Transport: "carrier-pigeon"}, testLogger()); err == nil {
		t.Fatal("expected error: unknown transport")
	}
}

func TestPushMFAOptions_TranslatesEachKnob(t *testing.T) {
	t.Parallel()
	if got := pushMFAOptions(config.MFAPushConfig{}); len(got) != 0 {
		t.Fatalf("zero-value config: got %d opts, want 0", len(got))
	}
	full := config.MFAPushConfig{PollInterval: 1, MaxWait: 2, ChannelNotify: true}
	if got := pushMFAOptions(full); len(got) != 3 {
		t.Fatalf("fully-set config: got %d opts, want 3 (poll_interval, max_wait, channel_notify)", len(got))
	}
	// Each knob is independently optional.
	if got := pushMFAOptions(config.MFAPushConfig{ChannelNotify: true}); len(got) != 1 {
		t.Fatalf("channel_notify only: got %d opts, want 1", len(got))
	}
}

func TestBuildSnapshotStorage_InlineFileUnknown(t *testing.T) {
	t.Parallel()
	if s, err := buildSnapshotStorage(config.SnapshotStorageConfig{Backend: "inline"}, testLogger()); err != nil || s == nil {
		t.Fatalf("inline: store=%v err=%v", s, err)
	}
	dir := filepath.Join(t.TempDir(), "snaps")
	if s, err := buildSnapshotStorage(config.SnapshotStorageConfig{Backend: "file", File: config.SnapshotFileConfig{Dir: dir}}, testLogger()); err != nil || s == nil {
		t.Fatalf("file: store=%v err=%v", s, err)
	}
	if _, err := buildSnapshotStorage(config.SnapshotStorageConfig{Backend: "s3"}, testLogger()); err == nil {
		t.Fatal("expected error: unknown storage backend")
	}
}

func TestBuildSnapshotSealer_NoneAndUnknown(t *testing.T) {
	t.Parallel()
	for _, backend := range []string{"", "none"} {
		if s, err := buildSnapshotSealer(config.SnapshotEncryptionConfig{Backend: backend}, testLogger()); err != nil || s == nil {
			t.Fatalf("backend=%q: sealer=%v err=%v", backend, s, err)
		}
	}
	if _, err := buildSnapshotSealer(config.SnapshotEncryptionConfig{Backend: "one-time-pad"}, testLogger()); err == nil {
		t.Fatal("expected error: unknown encryption backend")
	}
}

func TestBuildSnapshotSealer_PassphraseInlineFileAndMissing(t *testing.T) {
	t.Parallel()
	if s, err := buildSnapshotSealer(config.SnapshotEncryptionConfig{Backend: "passphrase", Passphrase: "hunter2"}, testLogger()); err != nil || s == nil {
		t.Fatalf("inline passphrase: sealer=%v err=%v", s, err)
	}

	path := filepath.Join(t.TempDir(), "pass.txt")
	if err := os.WriteFile(path, []byte("from-file-passphrase\n"), 0o600); err != nil {
		t.Fatalf("write passphrase file: %v", err)
	}
	if s, err := buildSnapshotSealer(config.SnapshotEncryptionConfig{Backend: "passphrase", PassphraseFile: path}, testLogger()); err != nil || s == nil {
		t.Fatalf("passphrase file: sealer=%v err=%v", s, err)
	}

	if _, err := buildSnapshotSealer(config.SnapshotEncryptionConfig{Backend: "passphrase"}, testLogger()); err == nil {
		t.Fatal("expected error: passphrase backend with neither passphrase nor passphrase_file")
	}
}

func TestBuildSnapshotSealer_AESGCMDelegatesToLoadAESGCMKey(t *testing.T) {
	t.Parallel()
	// Bad key: buildSnapshotSealer must surface LoadAESGCMKey's error rather
	// than constructing a sealer with a wrong-length key.
	if _, err := buildSnapshotSealer(config.SnapshotEncryptionConfig{Backend: "aes-gcm", Key: "too-short"}, testLogger()); err == nil {
		t.Fatal("expected error: undecodable aes-gcm key")
	}
	raw := make([]byte, 32)
	s, err := buildSnapshotSealer(config.SnapshotEncryptionConfig{Backend: "aes-256-gcm", Key: string(raw)}, testLogger())
	if err != nil || s == nil {
		t.Fatalf("aes-gcm: sealer=%v err=%v", s, err)
	}
}

func TestBuildTenantStoreBackend_MemorySqlitePostgresUnknown(t *testing.T) {
	t.Parallel()
	if s, err := buildTenantStoreBackend(config.TenantConfig{}, testLogger(), nil, postgresbackend.Dialect("")); err != nil || s == nil {
		t.Fatalf("memory: store=%v err=%v", s, err)
	}
	if _, err := buildTenantStoreBackend(config.TenantConfig{Backend: "sqlite"}, testLogger(), nil, postgresbackend.Dialect("")); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
	dsn := "file:" + filepath.Join(t.TempDir(), "tenant.db") + "?_journal=WAL"
	if s, err := buildTenantStoreBackend(config.TenantConfig{Backend: "sqlite", SQLite: config.TenantSQLiteConfig{DSN: dsn}}, testLogger(), nil, postgresbackend.Dialect("")); err != nil || s == nil {
		t.Fatalf("sqlite: store=%v err=%v", s, err)
	}
	if _, err := buildTenantStoreBackend(config.TenantConfig{Backend: "postgres"}, testLogger(), nil, postgresbackend.Dialect("")); err == nil {
		t.Fatal("expected error: postgres backend without a shared pool")
	}
	if _, err := buildTenantStoreBackend(config.TenantConfig{Backend: "carrier-pigeon"}, testLogger(), nil, postgresbackend.Dialect("")); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestSeedTenantStore_PutsTenantsAndDomains(t *testing.T) {
	t.Parallel()
	store := tenantmemory.New()
	cfg := config.TenantConfig{
		Tenants: []config.TenantSeedConfig{
			{ID: "t1", Slug: "acme", Name: "Acme"},
			{ID: "t2", Slug: "globex", Name: "Globex", Status: "suspended"},
		},
		Domains: []config.TenantDomainConfig{
			{Hostname: "acme.example.com", TenantID: "t1", IsApex: true},
		},
	}
	if err := seedTenantStore(store, cfg); err != nil {
		t.Fatalf("seedTenantStore: %v", err)
	}
	ctx := context.Background()
	t1, err := store.GetTenant(ctx, "t1")
	if err != nil || t1.Status != tenant.StatusActive {
		t.Fatalf("t1 = %+v err=%v, want status=active (the documented default)", t1, err)
	}
	t2, err := store.GetTenant(ctx, "t2")
	if err != nil || t2.Status != "suspended" {
		t.Fatalf("t2 = %+v err=%v, want status=suspended (explicit override honored)", t2, err)
	}
	d, err := store.GetDomain(ctx, "acme.example.com")
	if err != nil || d.TenantID != "t1" {
		t.Fatalf("domain = %+v err=%v", d, err)
	}
}

// TestSeedTenantStore_InvalidTenantErrors proves a bad seed entry surfaces
// as a wrapped, entry-identifying error rather than a silent partial seed —
// BuildTenantStore relies on this to decide whether to Close the store.
func TestSeedTenantStore_InvalidTenantErrors(t *testing.T) {
	t.Parallel()
	store := tenantmemory.New()
	cfg := config.TenantConfig{Tenants: []config.TenantSeedConfig{{ID: ""}}}
	if err := seedTenantStore(store, cfg); err == nil {
		t.Fatal("expected error: seed tenant with an empty ID fails Validate")
	}
}
