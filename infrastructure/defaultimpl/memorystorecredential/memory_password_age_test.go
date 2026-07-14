package memorystorecredential

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestMemoryPasswordCredentialStore_PasswordChangedAt_UnknownUser confirms an
// unstamped user returns an error (not a zero time treated as "always
// expired") — the login-time expiry gate (interfaces/sso
// rejectExpiredPassword) relies on this to fail open when it can't determine
// an age.
func TestMemoryPasswordCredentialStore_PasswordChangedAt_UnknownUser(t *testing.T) {
	t.Parallel()
	s := NewMemoryPasswordCredentialStore()
	if _, err := s.PasswordChangedAt(context.Background(), "nobody"); err == nil {
		t.Fatalf("PasswordChangedAt: want error for unknown user, got nil")
	}
}

// TestMemoryPasswordCredentialStore_PasswordChangedAt_StampedOnSet confirms
// SetPassword stamps a changedAt within a tight tolerance of "now" — this is
// the signal PasswordPolicyConfig.MaxAgeDays enforcement is built on.
func TestMemoryPasswordCredentialStore_PasswordChangedAt_StampedOnSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMemoryPasswordCredentialStore()

	before := time.Now()
	if err := s.SetPassword(ctx, "alice", "first-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	after := time.Now()

	got, err := s.PasswordChangedAt(ctx, "alice")
	if err != nil {
		t.Fatalf("PasswordChangedAt: %v", err)
	}
	if got.Before(before) || got.After(after) {
		t.Fatalf("PasswordChangedAt = %v; want between %v and %v", got, before, after)
	}
}

// TestMemoryPasswordCredentialStore_PasswordChangedAt_UpdatedOnChange
// confirms a SUBSEQUENT SetPassword call (self-service change / admin reset)
// re-stamps changedAt to the new time, resetting the age clock — a stale
// password shouldn't stay flagged expired forever after the user does
// exactly what the policy asks (change it).
func TestMemoryPasswordCredentialStore_PasswordChangedAt_UpdatedOnChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMemoryPasswordCredentialStore()

	if err := s.SetPassword(ctx, "alice", "first-password"); err != nil {
		t.Fatalf("SetPassword (first): %v", err)
	}
	first, err := s.PasswordChangedAt(ctx, "alice")
	if err != nil {
		t.Fatalf("PasswordChangedAt (first): %v", err)
	}

	// Force the two timestamps apart — real wall-clock resolution can
	// otherwise make two SetPassword calls in the same test indistinguishable.
	time.Sleep(2 * time.Millisecond)

	if err := s.SetPassword(ctx, "alice", "second-password"); err != nil {
		t.Fatalf("SetPassword (second): %v", err)
	}
	second, err := s.PasswordChangedAt(ctx, "alice")
	if err != nil {
		t.Fatalf("PasswordChangedAt (second): %v", err)
	}
	if !second.After(first) {
		t.Fatalf("PasswordChangedAt did not advance on change: first=%v second=%v", first, second)
	}
}

// TestMemoryPasswordCredentialStore_PasswordChangedAt_StampedOnHashImport
// confirms SetPasswordHash (the bulk/seed-import path — e.g.
// protocols/selfservice/verify_email.go) ALSO stamps changedAt, so an
// imported credential's age is measured from the import, not left unset.
func TestMemoryPasswordCredentialStore_PasswordChangedAt_StampedOnHashImport(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMemoryPasswordCredentialStore()

	h, err := bcrypt.GenerateFromPassword([]byte("imported-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	before := time.Now()
	if err := s.SetPasswordHash(ctx, "carol", string(h)); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	after := time.Now()

	got, err := s.PasswordChangedAt(ctx, "carol")
	if err != nil {
		t.Fatalf("PasswordChangedAt: %v", err)
	}
	if got.Before(before) || got.After(after) {
		t.Fatalf("PasswordChangedAt = %v; want between %v and %v", got, before, after)
	}
}
