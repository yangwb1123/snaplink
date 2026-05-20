package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAdminPasswordFile_AtomicAnd0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin-pw")

	if err := writeAdminPasswordFile(path, "swordfish-42"); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "swordfish-42" {
		t.Errorf("content = %q, want %q", got, "swordfish-42")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}

	// No leftover tmp file from atomic write.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".admin-password-") {
			t.Errorf("leftover tmp file: %s", e.Name())
		}
	}
}

func TestWriteAdminPasswordFile_OverwriteAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin-pw")

	if err := writeAdminPasswordFile(path, "first"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeAdminPasswordFile(path, "second"); err != nil {
		t.Fatalf("second write: %v", err)
	}

	data, _ := os.ReadFile(path)
	if got := strings.TrimSpace(string(data)); got != "second" {
		t.Errorf("after rewrite = %q, want second", got)
	}
}

func TestWriteAdminPasswordFile_FailsOnMissingDir(t *testing.T) {
	if err := writeAdminPasswordFile("/nonexistent-dir-12345/admin-pw", "x"); err == nil {
		t.Fatal("expected error writing to nonexistent dir; got nil — operator would never see the failure")
	}
}
