package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/config"
)

func mkAESGCMKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestLoadAESGCMKey_RawBytes(t *testing.T) {
	key := mkAESGCMKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := loadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
	if err != nil {
		t.Fatalf("loadAESGCMKey: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("key mismatch")
	}
}

func TestLoadAESGCMKey_HexEncoded(t *testing.T) {
	key := mkAESGCMKey(t)
	encoded := hex.EncodeToString(key)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.hex")
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := loadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
	if err != nil {
		t.Fatalf("loadAESGCMKey: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("key mismatch (hex)")
	}
}

func TestLoadAESGCMKey_Base64Encoded(t *testing.T) {
	key := mkAESGCMKey(t)
	encoded := base64.StdEncoding.EncodeToString(key)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.b64")
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := loadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
	if err != nil {
		t.Fatalf("loadAESGCMKey: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("key mismatch (base64)")
	}
}

func TestLoadAESGCMKey_InlineKeyHex(t *testing.T) {
	key := mkAESGCMKey(t)
	got, err := loadAESGCMKey(config.SnapshotEncryptionConfig{Key: hex.EncodeToString(key)})
	if err != nil {
		t.Fatalf("loadAESGCMKey: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("inline key mismatch")
	}
}

func TestLoadAESGCMKey_RejectsMissing(t *testing.T) {
	_, err := loadAESGCMKey(config.SnapshotEncryptionConfig{})
	if err == nil {
		t.Fatal("want error when neither key nor key_file set")
	}
}

func TestLoadAESGCMKey_RejectsWrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.bin")
	if err := os.WriteFile(path, []byte("only-16-bytes-yo"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := loadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
	if err == nil {
		t.Fatal("want error on wrong-length key")
	}
}

func TestLoadAESGCMKey_RejectsMissingFile(t *testing.T) {
	_, err := loadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: "/nonexistent/path"})
	if err == nil {
		t.Fatal("want error when key_file missing")
	}
}
