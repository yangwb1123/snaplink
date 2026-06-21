package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
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
	got, err := serverbuildstore.LoadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
	if err != nil {
		t.Fatalf("serverbuildstore.LoadAESGCMKey: %v", err)
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
	got, err := serverbuildstore.LoadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
	if err != nil {
		t.Fatalf("serverbuildstore.LoadAESGCMKey: %v", err)
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
	got, err := serverbuildstore.LoadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
	if err != nil {
		t.Fatalf("serverbuildstore.LoadAESGCMKey: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("key mismatch (base64)")
	}
}

func TestLoadAESGCMKey_InlineKeyHex(t *testing.T) {
	key := mkAESGCMKey(t)
	got, err := serverbuildstore.LoadAESGCMKey(config.SnapshotEncryptionConfig{Key: hex.EncodeToString(key)})
	if err != nil {
		t.Fatalf("serverbuildstore.LoadAESGCMKey: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("inline key mismatch")
	}
}

// TestLoadAESGCMKey_RawKeyEndingInNewlineByte is the deterministic
// regression for the flake: a raw 32-byte key whose final byte is 0x0A
// (or 0x0D) must load verbatim, not be truncated by newline trimming.
func TestLoadAESGCMKey_RawKeyEndingInNewlineByte(t *testing.T) {
	for _, last := range []byte{'\n', '\r'} {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1) // non-zero, deterministic
		}
		key[31] = last
		dir := t.TempDir()
		path := filepath.Join(dir, "raw.bin")
		if err := os.WriteFile(path, key, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		got, err := serverbuildstore.LoadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
		if err != nil {
			t.Fatalf("last=%#x: serverbuildstore.LoadAESGCMKey: %v", last, err)
		}
		if len(got) != 32 || string(got) != string(key) {
			t.Fatalf("last=%#x: raw key truncated/altered: got %d bytes", last, len(got))
		}
	}
}

func TestLoadAESGCMKey_RejectsMissing(t *testing.T) {
	_, err := serverbuildstore.LoadAESGCMKey(config.SnapshotEncryptionConfig{})
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
	_, err := serverbuildstore.LoadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: path})
	if err == nil {
		t.Fatal("want error on wrong-length key")
	}
}

func TestLoadAESGCMKey_RejectsMissingFile(t *testing.T) {
	_, err := serverbuildstore.LoadAESGCMKey(config.SnapshotEncryptionConfig{KeyFile: "/nonexistent/path"})
	if err == nil {
		t.Fatal("want error when key_file missing")
	}
}
