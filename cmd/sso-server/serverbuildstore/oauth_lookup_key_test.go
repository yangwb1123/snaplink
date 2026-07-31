package serverbuildstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

func TestResolveOAuthLookupHMACKeys(t *testing.T) {
	dir := t.TempDir()
	currentPath := filepath.Join(dir, "current")
	previousPath := filepath.Join(dir, "previous")
	if err := os.WriteFile(currentPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previousPath, []byte("abcdef0123456789abcdef0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := ResolveOAuthLookupHMACKeys(config.OAuthSQLiteConfig{
		LookupHMACKeyFile: currentPath, LookupHMACPreviousKeyFile: previousPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || len(keys[0]) != 32 || len(keys[1]) != 32 {
		t.Fatalf("resolved key lengths = %v, %v", len(keys[0]), len(keys[1]))
	}
	redisKeys, err := ResolveOAuthRedisLookupHMACKeys(config.OAuthRedisConfig{
		LookupHMACKeyFile: currentPath, LookupHMACPreviousKeyFile: previousPath,
	})
	if err != nil || len(redisKeys) != 2 {
		t.Fatalf("redis resolved keys = %d, err = %v", len(redisKeys), err)
	}
}

func TestResolveOAuthLookupHMACKeysRejectsUnsafeRotationConfig(t *testing.T) {
	_, err := ResolveOAuthLookupHMACKeys(config.OAuthSQLiteConfig{
		LookupHMACPreviousKeyFile: "previous",
	})
	if err == nil || !strings.Contains(err.Error(), "requires lookup_hmac_key_file") {
		t.Fatalf("err = %v; want current-key requirement", err)
	}
	_, err = ResolveOAuthRedisLookupHMACKeys(config.OAuthRedisConfig{
		LookupHMACPreviousKeyFile: "previous",
	})
	if err == nil || !strings.Contains(err.Error(), "oauth.redis.lookup_hmac_previous_key_file") {
		t.Fatalf("redis err = %v; want redis-scoped current-key requirement", err)
	}
}

func TestResolveOAuthLookupHMACKeysRejectsShortKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(path, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ResolveOAuthLookupHMACKeys(config.OAuthSQLiteConfig{LookupHMACKeyFile: path})
	if err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("err = %v; want minimum key length", err)
	}
}
