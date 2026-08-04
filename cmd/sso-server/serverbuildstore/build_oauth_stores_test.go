package serverbuildstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

func TestBuildAuthCodeStore_MemoryRedisUnknown(t *testing.T) {
	t.Parallel()
	if s, err := BuildAuthCodeStore(config.OAuthConfig{}, nil, nil, ""); err != nil || s == nil {
		t.Fatalf("memory: store=%v err=%v", s, err)
	}
	if _, err := BuildAuthCodeStore(config.OAuthConfig{Backend: "redis"}, nil, nil, ""); err == nil {
		t.Fatal("expected error: redis backend without a redis client")
	}
	if _, err := BuildAuthCodeStore(config.OAuthConfig{Backend: "carrier-pigeon"}, nil, nil, ""); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

// TestBuildRefreshTokenStore_MemoryHonorsRotationCap proves the memory
// path's rotation-cap knobs are actually wired through, not dropped —
// the redis peer once shipped without this cap (see the errRedisNotConfigured
// helper's sibling wiring in build_oauth_stores.go).
func TestBuildRefreshTokenStore_MemoryHonorsRotationCap(t *testing.T) {
	t.Parallel()
	s, err := BuildRefreshTokenStore(config.OAuthConfig{
		RefreshToken: config.OAuthRefreshTokenConfig{
			OAuthStoreConfig: config.OAuthStoreConfig{MaxRotationsPerWindow: 5},
		},
	}, nil, nil, "")
	if err != nil || s == nil {
		t.Fatalf("memory: store=%v err=%v", s, err)
	}
	mem, ok := s.(*defaultimpl.MemoryRefreshTokenStore)
	if !ok {
		t.Fatalf("store type = %T, want *defaultimpl.MemoryRefreshTokenStore", s)
	}
	if mem.MaxRotationsPerWindow != 5 {
		t.Errorf("MaxRotationsPerWindow = %d, want 5 (cfg not wired through)", mem.MaxRotationsPerWindow)
	}
	if _, err := BuildRefreshTokenStore(config.OAuthConfig{Backend: "redis"}, nil, nil, ""); err == nil {
		t.Fatal("expected error: redis backend without a redis client")
	}
	if _, err := BuildRefreshTokenStore(config.OAuthConfig{Backend: "carrier-pigeon"}, nil, nil, ""); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildDeviceCodeStore_MemoryRedisUnknown(t *testing.T) {
	t.Parallel()
	if s, err := BuildDeviceCodeStore(config.OAuthConfig{}, nil, nil, ""); err != nil || s == nil {
		t.Fatalf("memory: store=%v err=%v", s, err)
	}
	if _, err := BuildDeviceCodeStore(config.OAuthConfig{Backend: "redis"}, nil, nil, ""); err == nil {
		t.Fatal("expected error: redis backend without a redis client")
	}
	if _, err := BuildDeviceCodeStore(config.OAuthConfig{Backend: "carrier-pigeon"}, nil, nil, ""); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestBuildPARStore_MemoryRedisUnknown(t *testing.T) {
	t.Parallel()
	if s, err := BuildPARStore(config.OAuthConfig{}, nil, nil, ""); err != nil || s == nil {
		t.Fatalf("memory: store=%v err=%v", s, err)
	}
	if _, err := BuildPARStore(config.OAuthConfig{Backend: "redis"}, nil, nil, ""); err == nil {
		t.Fatal("expected error: redis backend without a redis client")
	}
	if _, err := BuildPARStore(config.OAuthConfig{Backend: "carrier-pigeon"}, nil, nil, ""); err == nil {
		t.Fatal("expected error: unknown backend")
	}
}

func TestResolvePairwiseSalt_InlineFileAndPrecedence(t *testing.T) {
	t.Parallel()
	if got, err := ResolvePairwiseSalt(config.PairwiseSubjectsConfig{Salt: "inline"}); err != nil || got != "inline" {
		t.Fatalf("inline: got %q err %v", got, err)
	}
	if got, err := ResolvePairwiseSalt(config.PairwiseSubjectsConfig{}); err != nil || got != "" {
		t.Fatalf("empty: got %q err %v, want empty salt + no error (SDK default fallback)", got, err)
	}

	path := filepath.Join(t.TempDir(), "salt.txt")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write salt file: %v", err)
	}
	// File wins even when Salt is also set.
	got, err := ResolvePairwiseSalt(config.PairwiseSubjectsConfig{Salt: "inline", SaltFile: path})
	if err != nil {
		t.Fatalf("ResolvePairwiseSalt: %v", err)
	}
	if got != "from-file" {
		t.Errorf("got %q, want %q (file must win over inline)", got, "from-file")
	}
}

func TestResolvePairwiseSalt_MissingFile(t *testing.T) {
	t.Parallel()
	if _, err := ResolvePairwiseSalt(config.PairwiseSubjectsConfig{SaltFile: "/no/such/salt"}); err == nil {
		t.Fatal("expected error reading missing salt file")
	}
}

func TestResolvePIISalt_BothEmptyIsAnError(t *testing.T) {
	t.Parallel()
	// A silently-empty salt makes hash inversion trivial, so this MUST be a
	// loud boot-time error, unlike ResolvePairwiseSalt's fallback default.
	if _, err := ResolvePIISalt(config.AuditPIIRedactionConfig{Enabled: true}); err == nil {
		t.Fatal("expected error: pii_redaction enabled with no salt or salt_file")
	}
}

func TestResolvePIISalt_InlineSalt(t *testing.T) {
	t.Parallel()
	got, err := ResolvePIISalt(config.AuditPIIRedactionConfig{Enabled: true, Salt: "pepper"})
	if err != nil || got != "pepper" {
		t.Fatalf("got %q err %v, want %q, nil", got, err, "pepper")
	}
}

func TestResolvePIISalt_FileWinsOverInlineAndEmptyFileIsAnError(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pii-salt.txt")
	if err := os.WriteFile(path, []byte("file-salt\n"), 0o600); err != nil {
		t.Fatalf("write salt file: %v", err)
	}
	got, err := ResolvePIISalt(config.AuditPIIRedactionConfig{Enabled: true, Salt: "pepper", SaltFile: path})
	if err != nil {
		t.Fatalf("ResolvePIISalt: %v", err)
	}
	if got != "file-salt" {
		t.Errorf("got %q, want %q (file must win over inline)", got, "file-salt")
	}

	emptyPath := filepath.Join(t.TempDir(), "empty-salt.txt")
	if err := os.WriteFile(emptyPath, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write empty salt file: %v", err)
	}
	if _, err := ResolvePIISalt(config.AuditPIIRedactionConfig{Enabled: true, SaltFile: emptyPath}); err == nil {
		t.Fatal("expected error: salt file resolves to an empty string")
	}
}

func TestResolvePIISalt_MissingFile(t *testing.T) {
	t.Parallel()
	if _, err := ResolvePIISalt(config.AuditPIIRedactionConfig{Enabled: true, SaltFile: "/no/such/salt"}); err == nil {
		t.Fatal("expected error reading missing salt file")
	}
}
