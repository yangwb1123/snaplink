package serverbuildauthn

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/shared/security"
)

func TestBuildPairwiseSubjectStore_MemorySqlitePostgresUnknown(t *testing.T) {
	t.Parallel()
	s, mode, err := BuildPairwiseSubjectStore(config.PairwiseSubjectsConfig{}, nil, "")
	if err != nil || s == nil || mode == "" {
		t.Fatalf("memory: store=%v mode=%q err=%v", s, mode, err)
	}
	if _, _, err := BuildPairwiseSubjectStore(config.PairwiseSubjectsConfig{Backend: "sqlite"}, nil, ""); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
	dsn := "file:" + filepath.Join(t.TempDir(), "pairwise.db") + "?_journal=WAL"
	s, mode, err = BuildPairwiseSubjectStore(config.PairwiseSubjectsConfig{
		Backend: "sqlite",
		SQLite:  config.PairwiseSubjectsSQLiteCfg{DSN: dsn},
	}, nil, "")
	if err != nil || s == nil || mode == "" {
		t.Fatalf("sqlite: store=%v mode=%q err=%v", s, mode, err)
	}
	if _, _, err := BuildPairwiseSubjectStore(config.PairwiseSubjectsConfig{Backend: "postgres"}, nil, ""); err == nil {
		t.Fatal("expected error: postgres backend without a shared pool")
	}
	if _, _, err := BuildPairwiseSubjectStore(config.PairwiseSubjectsConfig{Backend: "carrier-pigeon"}, nil, ""); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildAccountLockout_MemoryAppliesPolicyOverrides(t *testing.T) {
	t.Parallel()
	l, mode, err := BuildAccountLockout(config.AccountLockoutConfig{
		MaxFailures:     3,
		LockoutDuration: time.Minute,
		FailureWindow:   2 * time.Minute,
	}, nil)
	if err != nil || l == nil || mode == "" {
		t.Fatalf("memory: lockout=%v mode=%q err=%v", l, mode, err)
	}
	mem, ok := l.(*security.MemoryAccountLockout)
	if !ok {
		t.Fatalf("type = %T, want *security.MemoryAccountLockout", l)
	}
	if mem.MaxFailures != 3 || mem.LockoutDuration != time.Minute || mem.FailureWindow != 2*time.Minute {
		t.Errorf("policy overrides not applied: %+v", mem)
	}
}

func TestBuildAccountLockout_SqliteRedisUnknown(t *testing.T) {
	t.Parallel()
	if _, _, err := BuildAccountLockout(config.AccountLockoutConfig{Backend: "sqlite"}, nil); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
	dsn := "file:" + filepath.Join(t.TempDir(), "lockout.db") + "?_journal=WAL"
	l, mode, err := BuildAccountLockout(config.AccountLockoutConfig{
		Backend:     "sqlite",
		SQLite:      config.AccountLockoutSQLiteConfig{DSN: dsn},
		MaxFailures: 7,
	}, nil)
	if err != nil || l == nil || mode == "" {
		t.Fatalf("sqlite: lockout=%v mode=%q err=%v", l, mode, err)
	}
	if _, _, err := BuildAccountLockout(config.AccountLockoutConfig{Backend: "redis"}, nil); err == nil {
		t.Fatal("expected error: redis backend without a redis client (via buildRedisLockout)")
	}
	if _, _, err := BuildAccountLockout(config.AccountLockoutConfig{Backend: "carrier-pigeon"}, nil); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildSubjectClientIndex_MemorySqliteRedisUnknown(t *testing.T) {
	t.Parallel()
	idx, mode, err := BuildSubjectClientIndex(config.BCLIndexConfig{}, nil)
	if err != nil || idx == nil || mode == "" {
		t.Fatalf("memory: idx=%v mode=%q err=%v", idx, mode, err)
	}
	if _, _, err := BuildSubjectClientIndex(config.BCLIndexConfig{Backend: "sqlite"}, nil); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
	dsn := "file:" + filepath.Join(t.TempDir(), "bcl.db") + "?_journal=WAL"
	idx, mode, err = BuildSubjectClientIndex(config.BCLIndexConfig{
		Backend: "sqlite",
		SQLite:  config.BCLIndexSQLiteConfig{DSN: dsn},
	}, nil)
	if err != nil || idx == nil || mode == "" {
		t.Fatalf("sqlite: idx=%v mode=%q err=%v", idx, mode, err)
	}
	if _, _, err := BuildSubjectClientIndex(config.BCLIndexConfig{Backend: "redis"}, nil); err == nil {
		t.Fatal("expected error: redis backend without a redis client")
	}
	if _, _, err := BuildSubjectClientIndex(config.BCLIndexConfig{Backend: "carrier-pigeon"}, nil); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildJTIReplayStore_MemorySqliteRedisUnknown(t *testing.T) {
	t.Parallel()
	s, mode, err := BuildJTIReplayStore(config.JTIReplayConfig{}, nil)
	if err != nil || s == nil || mode == "" {
		t.Fatalf("memory: store=%v mode=%q err=%v", s, mode, err)
	}
	if _, _, err := BuildJTIReplayStore(config.JTIReplayConfig{Backend: "sqlite"}, nil); err == nil {
		t.Fatal("expected error: sqlite backend requires a dsn")
	}
	dsn := "file:" + filepath.Join(t.TempDir(), "jti.db") + "?_journal=WAL"
	s, mode, err = BuildJTIReplayStore(config.JTIReplayConfig{
		Backend: "sqlite",
		SQLite:  config.JTIReplaySQLiteCfg{DSN: dsn},
	}, nil)
	if err != nil || s == nil || mode == "" {
		t.Fatalf("sqlite: store=%v mode=%q err=%v", s, mode, err)
	}
	if _, _, err := BuildJTIReplayStore(config.JTIReplayConfig{Backend: "redis"}, nil); err == nil {
		t.Fatal("expected error: redis backend without a redis client")
	}
	if _, _, err := BuildJTIReplayStore(config.JTIReplayConfig{Backend: "carrier-pigeon"}, nil); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

// buildAuthenticatorReplayStore is unexported — only reachable in-package.
// It backs the keypair/TOTP authenticators' shared replay defense: disabled
// jti_replay still gets a memory store (a shipped binary must not be
// replay-vulnerable by default), and enabled jti_replay defers entirely to
// BuildJTIReplayStore so the two never diverge.
func TestBuildAuthenticatorReplayStore_DisabledStillReturnsMemoryDefault(t *testing.T) {
	t.Parallel()
	s, mode, err := buildAuthenticatorReplayStore(config.JTIReplayConfig{Enabled: false}, nil)
	if err != nil || s == nil {
		t.Fatalf("store=%v mode=%q err=%v, want a non-nil default memory store", s, mode, err)
	}
}

func TestBuildAuthenticatorReplayStore_EnabledDefersToBuildJTIReplayStore(t *testing.T) {
	t.Parallel()
	// Enabled + an invalid backend must surface BuildJTIReplayStore's error —
	// proving the delegation, not a swallowed/duplicated switch.
	if _, _, err := buildAuthenticatorReplayStore(config.JTIReplayConfig{Enabled: true, Backend: "carrier-pigeon"}, nil); err == nil {
		t.Fatal("expected error: enabled jti_replay defers to BuildJTIReplayStore's own validation")
	}
}
