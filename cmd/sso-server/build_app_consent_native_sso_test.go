package main

import (
	"path/filepath"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/config"
	defaultimpl "github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

func TestWireLoginTransactionStoreRequiresSharedRedis(t *testing.T) {
	t.Parallel()
	b := &appBuilder{logger: quietLogger()}
	if err := b.wireLoginTransactionStore(); err != nil {
		t.Fatalf("nil config: %v", err)
	}
	if len(b.opts) != 0 {
		t.Fatalf("nil Redis unexpectedly wired %d options", len(b.opts))
	}

	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	b = &appBuilder{cfg: &config.Config{}, logger: quietLogger(), redis: rdb}
	if err := b.wireLoginTransactionStore(); err != nil {
		t.Fatalf("redis: %v", err)
	}
	if len(b.opts) != 1 {
		t.Fatalf("shared Redis wired %d options, want one login transaction store", len(b.opts))
	}
	_ = rdb.Close()
}

func TestWireLoginTransactionStoreReusesMFAStore(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryMFAChallengeStore()
	b := &appBuilder{
		cfg:               &config.Config{},
		logger:            quietLogger(),
		mfaChallengeStore: store,
	}
	if err := b.wireLoginTransactionStore(); err != nil {
		t.Fatalf("reuse MFA store: %v", err)
	}
	if b.loginTransactionStore != store {
		t.Fatal("login transaction store did not reuse configured MFA store")
	}
}

func TestWireLoginTransactionStoreBuildsConfiguredSQLiteWhenMFADisabled(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "login-transactions.db") + "?_journal=WAL"
	b := &appBuilder{
		cfg: &config.Config{MFA: config.MFAConfig{
			Challenge: config.MFAChallengeConfig{
				Backend: "sqlite",
				SQLite:  config.MFAChallengeSQLiteConfig{DSN: dsn},
			},
		}},
		logger: quietLogger(),
	}
	if err := b.wireLoginTransactionStore(); err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if len(b.opts) != 1 || b.loginTransactionStore == nil {
		t.Fatalf("sqlite transaction store not wired: opts=%d store=%T", len(b.opts), b.loginTransactionStore)
	}
	if closer, ok := b.loginTransactionStore.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			t.Fatalf("close sqlite transaction store: %v", err)
		}
	} else {
		t.Fatalf("sqlite transaction store %T is not closable", b.loginTransactionStore)
	}
}
