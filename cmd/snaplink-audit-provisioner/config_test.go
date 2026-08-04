package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRuntimeConfigReadsSecretOnlyFromDedicatedEnvOrFile(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := validConfigEnv()
	delete(env, "SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET")
	env["SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET_FILE"] = secretPath
	config, err := parseRuntimeConfig([]string{"--one-shot"}, mapGetenv(env), &strings.Builder{})
	if err != nil || config.ClientSecret != "file-secret" {
		t.Fatalf("config=%+v error=%v", config, err)
	}
	env["SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET"] = "env-secret"
	if _, err := parseRuntimeConfig(nil, mapGetenv(env), &strings.Builder{}); err == nil {
		t.Fatal("two secret sources were accepted")
	}
}

func TestParseRuntimeConfigRejectsUnsafeSecretFile(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("secret"), 0o666); err != nil {
		t.Fatal(err)
	}
	env := validConfigEnv()
	delete(env, "SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET")
	env["SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET_FILE"] = secretPath
	if _, err := parseRuntimeConfig(nil, mapGetenv(env), &strings.Builder{}); err == nil {
		t.Fatal("unsafe secret file was accepted")
	}
}

func TestParseRuntimeConfigRejectsCRLFSecretFile(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("secret\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := validConfigEnv()
	delete(env, "SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET")
	env["SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET_FILE"] = secretPath
	if _, err := parseRuntimeConfig(nil, mapGetenv(env), &strings.Builder{}); err == nil {
		t.Fatal("CRLF secret file was accepted")
	}
}

func TestReadSecretFileAcceptsKubernetesProjectedGenerationPath(t *testing.T) {
	mount := t.TempDir()
	generation := filepath.Join(mount, "..2026_08_04")
	if err := os.Mkdir(generation, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generation, "client-secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(generation), filepath.Join(mount, "..data")); err != nil {
		t.Fatal(err)
	}
	secret, err := readSecretFile(filepath.Join(mount, "..data", "client-secret"))
	if err != nil || secret != "secret" {
		t.Fatalf("secret=%q error=%v", secret, err)
	}
}

func TestParseRuntimeConfigRejectsPositionalArguments(t *testing.T) {
	if _, err := parseRuntimeConfig([]string{"unexpected"}, mapGetenv(validConfigEnv()), &strings.Builder{}); err == nil {
		t.Fatal("positional argument was accepted")
	}
}

func validConfigEnv() map[string]string {
	return map[string]string{
		"SNAPLINK_AUDIT_PROVISIONER_MANIFEST_FILE": "/safe/desired.json",
		"SNAPLINK_AUDIT_PROVISIONER_BASE_URL":      "https://audit.example",
		"SNAPLINK_AUDIT_PROVISIONER_TOKEN_URL":     "https://issuer.example/token",
		"SNAPLINK_AUDIT_PROVISIONER_CLIENT_ID":     "audit-provisioner",
		"SNAPLINK_AUDIT_PROVISIONER_CLIENT_SECRET": "env-secret",
		"SNAPLINK_AUDIT_PROVISIONER_RESOURCE":      "audit-control",
	}
}

func mapGetenv(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}
