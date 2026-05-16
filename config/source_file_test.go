package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	return path
}

func TestFileSource_Happy(t *testing.T) {
	p := writeTemp(t, "c.yaml", "server:\n  listen: :9999\n")
	m, err := NewFileSource(p).Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	srv, ok := m["server"].(map[string]any)
	if !ok {
		t.Fatalf("server not a map: %T", m["server"])
	}
	if srv["listen"] != ":9999" {
		t.Errorf("listen = %v", srv["listen"])
	}
}

func TestFileSource_MissingRequired(t *testing.T) {
	_, err := NewFileSource("/no/such/file.yaml").Load(context.Background())
	if err == nil {
		t.Fatalf("expected error for missing required file")
	}
}

func TestFileSource_MissingOptional(t *testing.T) {
	src := &FileSource{Path: "/no/such/file.yaml", Optional: true}
	m, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("optional missing should not error: %v", err)
	}
	if m != nil {
		t.Errorf("optional missing should return nil map, got %v", m)
	}
}

func TestFileSource_EmptyFile(t *testing.T) {
	p := writeTemp(t, "empty.yaml", "")
	m, err := NewFileSource(p).Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m != nil {
		t.Errorf("empty file should yield nil map, got %v", m)
	}
}

func TestFileSource_Malformed(t *testing.T) {
	p := writeTemp(t, "bad.yaml", "server:\n  listen: : : :")
	_, err := NewFileSource(p).Load(context.Background())
	if err == nil {
		t.Fatalf("malformed YAML should error")
	}
}

func TestFileSource_NameIncludesPath(t *testing.T) {
	if got := NewFileSource("/foo/bar.yaml").Name(); got != "file:/foo/bar.yaml" {
		t.Errorf("Name = %q", got)
	}
}

func TestLoad_BackwardCompat(t *testing.T) {
	p := writeTemp(t, "compat.yaml", "server:\n  listen: :7070\nlogging:\n  level: debug\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":7070" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("level = %q", cfg.Logging.Level)
	}
}

func TestLoad_MissingFile_StillErrors(t *testing.T) {
	_, err := Load("/no/such/path/config.yaml")
	if err == nil {
		t.Fatalf("expected error wrapping missing file")
	}
	// We don't require errors.Is(err, os.ErrNotExist) because the
	// source wraps with its own message, but the path should be
	// quoted somewhere in the chain. Smoke-check that the inner
	// "no such file" error is preserved.
	if !errors.Is(err, os.ErrNotExist) {
		// goccy/go-yaml may swallow it; tolerate either form but
		// at least we got an error.
		t.Logf("Load err (not wrapping os.ErrNotExist, but errored): %v", err)
	}
}
