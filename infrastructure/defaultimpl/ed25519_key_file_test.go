package defaultimpl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEd25519KeyFileLoadOrGenerate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")

	// 首次：生成 + 写 PEM（0600）
	first, err := loadOrGenerateEd25519Key(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perm = %o, want 600", perm)
	}

	// 再次：从文件加载，密钥一致
	second, err := loadOrGenerateEd25519Key(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !first.Equal(second) {
		t.Fatal("loaded key differs from generated key")
	}
}

func TestEd25519KeyFileKidStableAcrossIssuers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")

	first := NewEd25519JWTIssuer(WithEd25519KeyFile(path))
	second := NewEd25519JWTIssuer(WithEd25519KeyFile(path))

	if first.KeyID() == "" || first.KeyID() != second.KeyID() {
		t.Fatalf("kid not stable across issuers: %q vs %q", first.KeyID(), second.KeyID())
	}
}

func TestEd25519KeyFileCorruptFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateEd25519Key(path); err == nil {
		t.Fatal("corrupt key file must fail closed")
	}
}
