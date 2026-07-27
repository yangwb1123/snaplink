package serverbuildstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

func TestBuildNetworkStore_DisabledReturnsNils(t *testing.T) {
	t.Parallel()
	store, kind, err := BuildNetworkStore(&config.NetworkConfig{Enabled: false}, testLogger())
	if err != nil || store != nil || kind != "" {
		t.Fatalf("store=%v kind=%q err=%v, want (nil, \"\", nil)", store, kind, err)
	}
}

// TestBuildNetworkStore_MemorySeedsPolicies proves the declared seed
// policies actually land in the store — a silently-dropped seed would
// leave every advertised base-URL policy missing at request time.
func TestBuildNetworkStore_MemorySeedsPolicies(t *testing.T) {
	t.Parallel()
	cfg := &config.NetworkConfig{
		Enabled: true,
		Store:   "memory",
		Policies: []config.NetworkPolicySeed{
			{Name: "internal", CIDRs: []string{"10.0.0.0/8"}, Priority: 10},
		},
	}
	store, kind, err := BuildNetworkStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildNetworkStore: %v", err)
	}
	if store == nil || kind != "memory" {
		t.Fatalf("store=%v kind=%q, want non-nil store + kind=memory", store, kind)
	}
	defer func() { _ = store.Close() }()
	got, err := store.Get(context.Background(), "internal")
	if err != nil || got == nil {
		t.Fatalf("seeded policy not found: got=%v err=%v", got, err)
	}
}

func TestBuildNetworkStore_UnknownStoreErrors(t *testing.T) {
	t.Parallel()
	_, _, err := BuildNetworkStore(&config.NetworkConfig{Enabled: true, Store: "s3"}, testLogger())
	if err == nil {
		t.Fatal("expected error for unknown network.store")
	}
}

func TestBuildSnapshotSubsystem_DisabledAndInlineSmoke(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	if pipe, store, err := BuildSnapshotSubsystem(cfg, testLogger()); err != nil || pipe != nil || store != nil {
		t.Fatalf("disabled: pipe=%v store=%v err=%v, want all nil", pipe, store, err)
	}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "inline"
	pipe, store, err := BuildSnapshotSubsystem(cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildSnapshotSubsystem: %v", err)
	}
	if pipe == nil || store == nil {
		t.Fatal("pipe or store nil with inline backend enabled")
	}
}

func TestLoadAESGCMKey_RawHexAndMissing(t *testing.T) {
	t.Parallel()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	if got, err := LoadAESGCMKey(config.SnapshotEncryptionConfig{Key: string(raw)}); err != nil || len(got) != 32 {
		t.Fatalf("raw key: got len=%d err=%v", len(got), err)
	}
	if got, err := LoadAESGCMKey(config.SnapshotEncryptionConfig{Key: hex.EncodeToString(raw)}); err != nil || len(got) != 32 {
		t.Fatalf("hex key: got len=%d err=%v", len(got), err)
	}
	if got, err := LoadAESGCMKey(config.SnapshotEncryptionConfig{Key: base64.StdEncoding.EncodeToString(raw)}); err != nil || len(got) != 32 {
		t.Fatalf("base64 key: got len=%d err=%v", len(got), err)
	}
	if _, err := LoadAESGCMKey(config.SnapshotEncryptionConfig{}); err == nil {
		t.Fatal("expected error: neither key nor key_file set")
	}
	if _, err := LoadAESGCMKey(config.SnapshotEncryptionConfig{Key: "too-short"}); err == nil {
		t.Fatal("expected error: key does not decode to 32 bytes under any scheme")
	}
}

// TestLoadAESGCMKey_RawFileNotTrimmed proves a 32-byte binary key file is
// used byte-for-byte even when its last byte happens to be a newline —
// trimming would silently truncate a raw 32-byte KMS-issued DEK to 31
// bytes and fail every subsequent Seal/Open with a cryptic AEAD error.
func TestLoadAESGCMKey_RawFileNotTrimmed(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	key[31] = '\n'
	path := filepath.Join(t.TempDir(), "key.bin")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	got, err := LoadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
	if err != nil {
		t.Fatalf("LoadAESGCMKey: %v", err)
	}
	if len(got) != 32 || got[31] != '\n' {
		t.Fatalf("got %d bytes (last=%q); want the raw 32 bytes untrimmed", len(got), got)
	}
}
