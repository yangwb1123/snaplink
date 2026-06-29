package defaultrisk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDictionaryPasswordHealthChecker_WeakBuiltin(t *testing.T) {
	t.Parallel()
	c, err := NewDictionaryPasswordHealthChecker(DictionaryPasswordHealthConfig{})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	sig, err := c.Check(context.Background(), "password")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig == nil {
		t.Fatal("expected a signal for a built-in weak password, got nil")
	}
	if !sig.Weak {
		t.Errorf("Weak = false, want true")
	}
	if sig.Reason != reasonWeakDictionary {
		t.Errorf("Reason = %q, want %q", sig.Reason, reasonWeakDictionary)
	}
}

func TestDictionaryPasswordHealthChecker_StrongReturnsNil(t *testing.T) {
	t.Parallel()
	c, err := NewDictionaryPasswordHealthChecker(DictionaryPasswordHealthConfig{})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	// A high-entropy passphrase the built-in set does not contain.
	sig, err := c.Check(context.Background(), "correct-horse-battery-staple-9x!Q")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig != nil {
		t.Errorf("expected nil signal for a strong password, got %+v", sig)
	}
}

func TestDictionaryPasswordHealthChecker_OperatorFileExtends(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "weak.txt")
	// Mix in a comment + blank line to prove they are skipped, plus a
	// custom entry the built-in set does not carry.
	const content = "# operator additions\n\nhunter2-corp-special\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	c, err := NewDictionaryPasswordHealthChecker(DictionaryPasswordHealthConfig{WeakPasswordFile: path})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	sig, err := c.Check(context.Background(), "hunter2-corp-special")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if sig == nil || !sig.Weak {
		t.Fatalf("operator-file weak password not flagged: %+v", sig)
	}
	// The comment line must NOT have been folded in as a literal entry.
	if s, _ := c.Check(context.Background(), "# operator additions"); s != nil {
		t.Errorf("comment line treated as a weak password: %+v", s)
	}
	// The built-in set is still present alongside the extension.
	if s, _ := c.Check(context.Background(), "123456"); s == nil {
		t.Errorf("built-in entry lost after extending from file")
	}
}

func TestDictionaryPasswordHealthChecker_MissingFileIsLoud(t *testing.T) {
	t.Parallel()
	_, err := NewDictionaryPasswordHealthChecker(DictionaryPasswordHealthConfig{
		WeakPasswordFile: filepath.Join(t.TempDir(), "does-not-exist.txt"),
	})
	if err == nil {
		t.Fatal("expected a constructor error for a missing extension file, got nil")
	}
}
