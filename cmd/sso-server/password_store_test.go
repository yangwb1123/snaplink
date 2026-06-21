package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildauthn"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"golang.org/x/crypto/bcrypt"
)

func TestBuildPasswordCredentialStore_DisabledByDefault(t *testing.T) {
	s, err := buildPasswordCredentialStore(config.SelfServiceStoreConfig{})
	if err != nil {
		t.Fatalf("disabled build: %v", err)
	}
	if s != nil {
		t.Fatalf("expected nil store when backend empty, got %T", s)
	}
}

func TestBuildPasswordCredentialStore_SQLiteNeedsDSN(t *testing.T) {
	if _, err := buildPasswordCredentialStore(config.SelfServiceStoreConfig{Backend: "sqlite"}); err == nil {
		t.Fatal("expected error when sqlite backend has empty DSN")
	}
}

func TestBuildPasswordCredentialStore_UnknownBackend(t *testing.T) {
	if _, err := buildPasswordCredentialStore(config.SelfServiceStoreConfig{Backend: "bogus"}); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

// writeHashFile writes a bcrypt hash of pw to a temp file and returns the path.
func writeHashFile(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	p := filepath.Join(t.TempDir(), "h")
	if err := os.WriteFile(p, h, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// TestBuildStoredPasswordVerifier_SeedsAndAuthenticates verifies the full
// stock-binary flow: YAML users are imported into the store by hash, login
// authenticates against the store, an unknown user fails, and a password
// changed in the store (as /me/password would) takes effect on next login.
func TestBuildStoredPasswordVerifier_SeedsAndAuthenticates(t *testing.T) {
	store := defaultimpl.NewMemoryPasswordCredentialStore()
	users := []config.PasswordUserConfig{
		{Username: "alice", SubjectID: "u-alice", BcryptHashFile: writeHashFile(t, "alice-pw")},
	}
	v, seeded, err := serverbuildauthn.BuildStoredPasswordVerifier(store, users, quietLogger())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if seeded != 1 {
		t.Fatalf("seeded=%d, want 1", seeded)
	}
	ctx := context.Background()

	// Login against the seeded store.
	res, err := v.Verify(ctx, "alice", "alice-pw")
	if err != nil {
		t.Fatalf("verify seeded: %v", err)
	}
	if res.UserID != "u-alice" || res.ExternalID != "alice" {
		t.Errorf("AuthResult=%+v, want u-alice / alice", res)
	}
	// Wrong password + unknown user both fail.
	if _, err := v.Verify(ctx, "alice", "wrong"); err == nil {
		t.Error("wrong password must fail")
	}
	if _, err := v.Verify(ctx, "mallory", "alice-pw"); err == nil {
		t.Error("unknown user must fail")
	}

	// Simulate POST /me/password changing the credential in the store.
	if err := store.SetPassword(ctx, "u-alice", "new-pw"); err != nil {
		t.Fatalf("set new password: %v", err)
	}
	if _, err := v.Verify(ctx, "alice", "alice-pw"); err == nil {
		t.Error("old password must stop working after change")
	}
	if _, err := v.Verify(ctx, "alice", "new-pw"); err != nil {
		t.Errorf("new password must work after change: %v", err)
	}
}
