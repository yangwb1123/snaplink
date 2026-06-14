package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/config"
)

// TestLoadSecretFile_TrimsTrailingNewline proves the loader matches
// the shell pattern `echo secret > file` — that emits a trailing
// newline that operators would be surprised to find baked into the
// stored secret.
func TestLoadSecretFile_TrimsTrailingNewline(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "k.secret")
	if err := os.WriteFile(tmp, []byte("topsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadSecretFile(tmp)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "topsecret" {
		t.Errorf("loadSecretFile = %q; want %q", got, "topsecret")
	}
}

// TestLoadSecretFile_RejectsEmpty — a file existing but empty would
// silently admit the empty string as a credential. Fail loud at
// boot instead.
func TestLoadSecretFile_RejectsEmpty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.secret")
	if err := os.WriteFile(tmp, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadSecretFile(tmp)
	if err == nil || !strings.Contains(err.Error(), "empty secret") {
		t.Fatalf("err = %v; want empty-secret error", err)
	}
}

// TestLoadSecretFile_MissingFileSurfaces — typo'd path → boot
// error, not silent zero-credential.
func TestLoadSecretFile_MissingFileSurfaces(t *testing.T) {
	if _, err := loadSecretFile("/no/such/secret"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestBuildAuthenticators_APIKeySeedAuthenticates proves a seeded
// (key_id, secret_file, subject_id) entry produces an authenticator
// whose Authenticate succeeds against the same secret. The
// previous wiring registered a hardcoded "ak_demo" demo key that
// no real caller could ever use against production credentials.
func TestBuildAuthenticators_APIKeySeedAuthenticates(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "k.secret")
	const secret = "rotateme"
	if err := os.WriteFile(tmp, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Authenticators.APIKey = &config.APIKeyConfig{
		Enabled: true,
		Keys: []config.APIKeyConfigEntry{{
			KeyID:      "ak_t",
			SecretFile: tmp,
			SubjectID:  "subject-t",
		}},
	}
	auths, _, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil)
	var apikey sso.Authenticator
	for _, a := range auths {
		if a.Name() == "apikey" {
			apikey = a
		}
	}
	if apikey == nil {
		t.Fatal("apikey authenticator not registered")
	}
	got, err := apikey.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"key_id": "ak_t", "secret": secret},
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got == nil || got.UserID != "subject-t" {
		t.Errorf("got = %+v; want subject_id=subject-t", got)
	}
}

// TestBuildAuthenticators_APIKeySkipsBadEntries proves per-entry
// fail-soft behavior — bad entries log + skip, valid ones still
// register, the authenticator stays available.
func TestBuildAuthenticators_APIKeySkipsBadEntries(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "k.secret")
	if err := os.WriteFile(tmp, []byte("good\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Authenticators.APIKey = &config.APIKeyConfig{
		Enabled: true,
		Keys: []config.APIKeyConfigEntry{
			{KeyID: "", SecretFile: tmp, SubjectID: "missing-id"},
			{KeyID: "good", SecretFile: tmp, SubjectID: "ok"},
			{KeyID: "bad-path", SecretFile: "/no/such/file", SubjectID: "missing-file"},
		},
	}
	auths, _, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil)
	found := false
	for _, a := range auths {
		if a.Name() == "apikey" {
			found = true
		}
	}
	if !found {
		t.Fatal("apikey authenticator was dropped despite a valid seed entry")
	}
}

// TestBuildAuthenticators_APIKeyEmptyKeysList — operator opts in
// without seeding anything (e.g. expecting an admin RPC to seed
// later). Authenticator still registers; it simply rejects every
// authentication attempt with unknown-key until seeded.
func TestBuildAuthenticators_APIKeyEmptyKeysList(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.APIKey = &config.APIKeyConfig{Enabled: true}
	auths, _, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil)
	for _, a := range auths {
		if a.Name() == "apikey" {
			return
		}
	}
	t.Fatal("apikey authenticator not registered with empty keys list")
}
