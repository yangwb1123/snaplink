package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/config"
	"golang.org/x/crypto/bcrypt"
)

// TestLoadBcryptHashFile_GoodHash proves the helper accepts a real
// bcrypt hash and returns it byte-for-byte.
func TestLoadBcryptHashFile_GoodHash(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	path := filepath.Join(t.TempDir(), "a.bcrypt")
	if err := os.WriteFile(path, hash, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadBcryptHashFile(path)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if string(got) != string(hash) {
		t.Fatalf("got = %q; want %q", got, hash)
	}
}

// TestLoadBcryptHashFile_TolerateTrailingNewline — `echo` writes a
// trailing \n; the loader strips it so operators using echo don't
// silently end up with a hash that bcrypt.CompareHashAndPassword
// rejects.
func TestLoadBcryptHashFile_TolerateTrailingNewline(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	path := filepath.Join(t.TempDir(), "a.bcrypt")
	if err := os.WriteFile(path, append(hash, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadBcryptHashFile(path)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if string(got) != string(hash) {
		t.Fatalf("got = %q; want %q (trailing newline not stripped)", got, hash)
	}
}

// TestLoadBcryptHashFile_RejectsPlaintext — guards the "operator
// wrote the plaintext password to the hash file" mistake. Without
// the prefix check, the verifier would silently never authenticate
// anyone (bcrypt would compare the plaintext against itself with
// formatting overhead and always fail) without telling the
// operator why.
func TestLoadBcryptHashFile_RejectsPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrong.bcrypt")
	if err := os.WriteFile(path, []byte("mypassword\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadBcryptHashFile(path)
	if err == nil || !strings.Contains(err.Error(), "not a bcrypt hash") {
		t.Fatalf("err = %v; want bcrypt-prefix error", err)
	}
}

// TestLoadBcryptHashFile_RejectsMultiLine — a file with multiple
// hashes (operator concatenated several together?) is ambiguous.
// Reject explicitly.
func TestLoadBcryptHashFile_RejectsMultiLine(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	path := filepath.Join(t.TempDir(), "multi.bcrypt")
	if err := os.WriteFile(path, append(hash, '\n', 'X', '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadBcryptHashFile(path)
	if err == nil || !strings.Contains(err.Error(), "multi-line") {
		t.Fatalf("err = %v; want multi-line error", err)
	}
}

// TestLoadBcryptHashFile_RejectsEmpty — empty file → boot error,
// not silent zero-credential authenticator.
func TestLoadBcryptHashFile_RejectsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.bcrypt")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBcryptHashFile(path); err == nil {
		t.Fatal("expected error for empty file")
	}
}

// TestBcryptVerifier_CorrectPasswordAuthenticates proves the
// happy path: seed a (username, hash) entry, supply the matching
// password, get back the configured subject_id.
func TestBcryptVerifier_CorrectPasswordAuthenticates(t *testing.T) {
	const username, password = "alice", "s3cret!"
	hashPath := writeBcryptHashFile(t, password)
	users := []config.PasswordUserConfig{{
		Username: username, BcryptHashFile: hashPath, SubjectID: "user-alice",
	}}
	verifier, seeded := buildBcryptPasswordVerifier(users, quietLogger())
	if seeded != 1 {
		t.Fatalf("seeded = %d; want 1", seeded)
	}
	got, err := verifier.Verify(context.Background(), username, password)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got == nil || got.UserID != "user-alice" || got.ExternalID != username {
		t.Fatalf("got = %+v; want subject_id=user-alice, ext=%s", got, username)
	}
}

// TestBcryptVerifier_WrongPasswordRejected — correct username,
// wrong password → generic error. Locks the no-info-leak surface.
func TestBcryptVerifier_WrongPasswordRejected(t *testing.T) {
	hashPath := writeBcryptHashFile(t, "right")
	users := []config.PasswordUserConfig{{
		Username: "u", BcryptHashFile: hashPath, SubjectID: "s",
	}}
	verifier, _ := buildBcryptPasswordVerifier(users, quietLogger())
	if _, err := verifier.Verify(context.Background(), "u", "wrong"); err == nil {
		t.Fatal("expected error for wrong password")
	}
}

// TestBcryptVerifier_UnknownUserRejected — unknown username must
// fail with the SAME error string the wrong-password path returns.
// /auth/login responds with a generic invalid_credentials wrap; a
// distinguishable error here would let an attacker enumerate
// registered usernames over the audit log.
func TestBcryptVerifier_UnknownUserRejected(t *testing.T) {
	hashPath := writeBcryptHashFile(t, "p")
	users := []config.PasswordUserConfig{{
		Username: "u", BcryptHashFile: hashPath, SubjectID: "s",
	}}
	verifier, _ := buildBcryptPasswordVerifier(users, quietLogger())
	_, errKnown := verifier.Verify(context.Background(), "u", "wrong")
	_, errUnknown := verifier.Verify(context.Background(), "nobody", "anything")
	if errKnown == nil || errUnknown == nil {
		t.Fatal("both calls must error")
	}
	if errKnown.Error() != errUnknown.Error() {
		t.Errorf("error strings diverge: known=%q unknown=%q (leaks user enumeration)",
			errKnown.Error(), errUnknown.Error())
	}
}

// TestBcryptVerifier_UnknownUserTimingMatchesKnown proves the
// dummy-hash trick — bcrypt runs in both branches so wall-clock
// time can't be used to enumerate registered usernames. We can't
// assert an exact equality (bcrypt has natural jitter), but the
// known-user and unknown-user paths should sit in the same order
// of magnitude (within 3x at min cost). A bare lookup-miss would
// be 100x+ faster.
func TestBcryptVerifier_UnknownUserTimingMatchesKnown(t *testing.T) {
	hashPath := writeBcryptHashFile(t, "p")
	users := []config.PasswordUserConfig{{
		Username: "u", BcryptHashFile: hashPath, SubjectID: "s",
	}}
	verifier, _ := buildBcryptPasswordVerifier(users, quietLogger())
	const iters = 3
	known := timeVerify(t, verifier, "u", "wrong", iters)
	unknown := timeVerify(t, verifier, "nobody", "anything", iters)
	ratio := float64(unknown) / float64(known)
	if ratio < 1.0/3.0 || ratio > 3.0 {
		t.Errorf("timing ratio unknown/known = %.2f; want roughly 1 (both should bcrypt)",
			ratio)
	}
}

func timeVerify(t *testing.T, v interface {
	Verify(context.Context, string, string) (*sso.AuthResult, error)
}, u, p string, n int) time.Duration {
	t.Helper()
	start := time.Now()
	for range n {
		_, _ = v.Verify(context.Background(), u, p)
	}
	return time.Since(start)
}

// TestBcryptVerifier_BadSeedSkipped — a misconfigured entry
// (missing file) is logged + skipped, but valid entries still
// authenticate. Matches the per-entry fail-soft behavior
// keypair + apikey use.
func TestBcryptVerifier_BadSeedSkipped(t *testing.T) {
	goodHashPath := writeBcryptHashFile(t, "rightpw")
	users := []config.PasswordUserConfig{
		{Username: "missing", BcryptHashFile: "/no/such/file", SubjectID: "x"},
		{Username: "ok", BcryptHashFile: goodHashPath, SubjectID: "subject-ok"},
		{Username: "", BcryptHashFile: goodHashPath, SubjectID: "no-name"},
	}
	verifier, seeded := buildBcryptPasswordVerifier(users, quietLogger())
	if seeded != 1 {
		t.Fatalf("seeded = %d; want 1 (bad entries skipped)", seeded)
	}
	got, err := verifier.Verify(context.Background(), "ok", "rightpw")
	if err != nil {
		t.Fatalf("verify good entry: %v", err)
	}
	if got.UserID != "subject-ok" {
		t.Errorf("got subject %q; want subject-ok", got.UserID)
	}
}

// TestBuildAuthenticators_PasswordEmptyUsersRegisters — operator
// opts in without seeding (e.g. expecting an admin RPC to manage
// users later). Authenticator stays in the registry; every
// credential is rejected until seeded.
func TestBuildAuthenticators_PasswordEmptyUsersRegisters(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.Password = &config.PasswordConfig{Enabled: true}
	auths, _, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil)
	for _, a := range auths {
		if a.Name() == "password" {
			return
		}
	}
	t.Fatal("password authenticator not registered with empty users list")
}

// TestBuildAuthenticators_PasswordHealthEnabled proves the optional
// credential-health checker wires without error when enabled with no
// extension file (built-in dictionary only).
func TestBuildAuthenticators_PasswordHealthEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.Password = &config.PasswordConfig{
		Enabled: true,
		Health:  &config.PasswordHealthConfig{Enabled: true},
	}
	_, _, _, _, err := buildAuthenticators(cfg, quietLogger(), nil)
	if err != nil {
		t.Fatalf("unexpected error wiring password health: %v", err)
	}
}

// TestBuildAuthenticators_PasswordHealthMissingFileIsLoud proves a
// missing weak-password extension file fails the boot rather than
// silently degrading to the built-in set.
func TestBuildAuthenticators_PasswordHealthMissingFileIsLoud(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.Password = &config.PasswordConfig{
		Enabled: true,
		Health: &config.PasswordHealthConfig{
			Enabled:          true,
			WeakPasswordFile: filepath.Join(t.TempDir(), "missing.txt"),
		},
	}
	if _, _, _, _, err := buildAuthenticators(cfg, quietLogger(), nil); err == nil {
		t.Fatal("expected an error for a missing weak-password file, got nil")
	}
}

// writeBcryptHashFile hashes the given plaintext with bcrypt.MinCost
// (tests don't need production cost) and writes it to a tempdir
// file. Returns the path.
func writeBcryptHashFile(t *testing.T, plaintext string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt gen: %v", err)
	}
	path := filepath.Join(t.TempDir(), "h.bcrypt")
	if err := os.WriteFile(path, hash, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
