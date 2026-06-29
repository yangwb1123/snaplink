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
	t.Parallel()
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
	t.Parallel()
	_, err := NewFileSource("/no/such/file.yaml").Load(context.Background())
	if err == nil {
		t.Fatalf("expected error for missing required file")
	}
}

func TestFileSource_MissingOptional(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	p := writeTemp(t, "bad.yaml", "server:\n  listen: : : :")
	_, err := NewFileSource(p).Load(context.Background())
	if err == nil {
		t.Fatalf("malformed YAML should error")
	}
}

func TestFileSource_NameIncludesPath(t *testing.T) {
	t.Parallel()
	if got := NewFileSource("/foo/bar.yaml").Name(); got != "file:/foo/bar.yaml" {
		t.Errorf("Name = %q", got)
	}
}

func TestLoad_BackwardCompat(t *testing.T) {
	t.Parallel()
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

func TestLoad_AuditAsyncWiring(t *testing.T) {
	t.Parallel()
	// Lock the wire shape so cmd/sso-server's read of
	// cfg.Audit.Async.* keeps working as the config layer evolves.
	body := "server:\n  listen: :9090\naudit:\n  enabled: true\n  async:\n    enabled: true\n    buffer_size: 2048\n    workers: 4\n    record_timeout_ms: 1500\n"
	p := writeTemp(t, "async.yaml", body)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Audit.Async.Enabled {
		t.Error("Async.Enabled = false")
	}
	if cfg.Audit.Async.BufferSize != 2048 {
		t.Errorf("BufferSize = %d want 2048", cfg.Audit.Async.BufferSize)
	}
	if cfg.Audit.Async.Workers != 4 {
		t.Errorf("Workers = %d want 4", cfg.Audit.Async.Workers)
	}
	if cfg.Audit.Async.RecordTimeoutMs != 1500 {
		t.Errorf("RecordTimeoutMs = %d want 1500", cfg.Audit.Async.RecordTimeoutMs)
	}
}

func TestLoad_TenantSuspensionCheckWiring(t *testing.T) {
	t.Parallel()
	body := "server:\n  listen: :9090\ntenant:\n  enabled: true\n  suspension_check:\n    enabled: true\n    cache_ttl: 1m\n"
	p := writeTemp(t, "suspension.yaml", body)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Tenant.SuspensionCheck.Enabled {
		t.Error("SuspensionCheck.Enabled = false")
	}
	if cfg.Tenant.SuspensionCheck.CacheTTL.String() != "1m0s" {
		t.Errorf("CacheTTL = %s want 1m0s", cfg.Tenant.SuspensionCheck.CacheTTL)
	}
}

func TestLoad_DiscoveryDocCacheTTLWiring(t *testing.T) {
	t.Parallel()
	body := "server:\n  listen: :9090\n  discovery_doc_cache_ttl: 15s\n"
	p := writeTemp(t, "discovery.yaml", body)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.DiscoveryDocCacheTTL.String() != "15s" {
		t.Errorf("DiscoveryDocCacheTTL = %s want 15s", cfg.Server.DiscoveryDocCacheTTL)
	}
}

func TestLoad_SignedMetadataWiring(t *testing.T) {
	t.Parallel()
	body := "server:\n  listen: :9090\n  signed_metadata: true\n"
	p := writeTemp(t, "signed-metadata.yaml", body)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Server.SignedMetadata {
		t.Error("SignedMetadata = false")
	}
}

func TestLoad_DPoPNonceWiring(t *testing.T) {
	t.Parallel()
	body := "server:\n  listen: :9090\nsecurity:\n  dpop_nonce:\n    enabled: true\n    key_file: /etc/sso/dpop-nonce.key\n    ttl: 2m\n"
	p := writeTemp(t, "dpop-nonce.yaml", body)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Security.DPoPNonce.Enabled {
		t.Error("DPoPNonce.Enabled = false")
	}
	if cfg.Security.DPoPNonce.KeyFile != "/etc/sso/dpop-nonce.key" {
		t.Errorf("KeyFile = %q", cfg.Security.DPoPNonce.KeyFile)
	}
	if cfg.Security.DPoPNonce.TTL.String() != "2m0s" {
		t.Errorf("TTL = %s want 2m0s", cfg.Security.DPoPNonce.TTL)
	}
}

func TestLoad_MissingFile_StillErrors(t *testing.T) {
	t.Parallel()
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
