package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

func newTestPasswordStore(t *testing.T) *sqlite.PasswordCredentialStore {
	t.Helper()
	ps, err := sqlite.NewPasswordCredentialStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("NewPasswordCredentialStore: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	return ps
}

func TestSQLitePasswordStore_SetAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	ctx := context.Background()

	if err := ps.SetPassword(ctx, "alice", "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := ps.VerifyPassword(ctx, "alice", "correct horse battery staple"); err != nil {
		t.Fatalf("VerifyPassword (match): %v", err)
	}
}

func TestSQLitePasswordStore_WrongPasswordMismatch(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	ctx := context.Background()

	if err := ps.SetPassword(ctx, "alice", "right-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := ps.VerifyPassword(ctx, "alice", "wrong-password"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Fatalf("wrong password: got %v, want ErrPasswordMismatch", err)
	}
}

func TestSQLitePasswordStore_UnknownUserMismatch(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	// Unknown user MUST collapse to the same error as a real mismatch
	// (anti-enumeration) — the caller cannot distinguish absence from a
	// bad password.
	if err := ps.VerifyPassword(context.Background(), "ghost", "anything"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Fatalf("unknown user: got %v, want ErrPasswordMismatch", err)
	}
}

func TestSQLitePasswordStore_SetPasswordReplaces(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	ctx := context.Background()

	if err := ps.SetPassword(ctx, "alice", "old-password"); err != nil {
		t.Fatalf("SetPassword (old): %v", err)
	}
	if err := ps.SetPassword(ctx, "alice", "new-password"); err != nil {
		t.Fatalf("SetPassword (new): %v", err)
	}
	// The old password must no longer verify after replacement.
	if err := ps.VerifyPassword(ctx, "alice", "old-password"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Fatalf("old password after replace: got %v, want ErrPasswordMismatch", err)
	}
	// The new password must verify.
	if err := ps.VerifyPassword(ctx, "alice", "new-password"); err != nil {
		t.Fatalf("new password after replace: %v", err)
	}
}

func TestSQLitePasswordStore_EmptyUserIDRejected(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	// Matches the memory peer: an empty userID is never a valid key.
	if err := ps.SetPassword(context.Background(), "", "whatever"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Fatalf("empty userID: got %v, want ErrPasswordMismatch", err)
	}
}

func TestSQLitePasswordStore_SeparatesUsers(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	ctx := context.Background()

	if err := ps.SetPassword(ctx, "alice", "alice-pw"); err != nil {
		t.Fatalf("SetPassword alice: %v", err)
	}
	if err := ps.SetPassword(ctx, "bob", "bob-pw"); err != nil {
		t.Fatalf("SetPassword bob: %v", err)
	}
	// Each user's password verifies only against its own hash.
	if err := ps.VerifyPassword(ctx, "alice", "bob-pw"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Fatalf("alice with bob's pw: got %v, want ErrPasswordMismatch", err)
	}
	if err := ps.VerifyPassword(ctx, "bob", "bob-pw"); err != nil {
		t.Fatalf("bob with own pw: %v", err)
	}
}

func TestSQLitePasswordStore_PingWorks(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	if err := ps.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// TestSQLitePasswordStore_HasPassword pins the
// identitylink.PasswordPresenceChecker implementation this backend now
// satisfies: before it existed, a deployment using SQLite (the default,
// pure-Go, no-CGO backend) for password credentials always read as
// PasswordPresenceChecker-unimplemented, so the self-service identity-unlink
// "don't lock yourself out" guard fell CLOSED (assumed no password) even for
// a user who genuinely had one.
func TestSQLitePasswordStore_HasPassword(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	ctx := context.Background()

	if has, err := ps.HasPassword(ctx, "alice"); err != nil || has {
		t.Fatalf("HasPassword before SetPassword = (%v, %v), want (false, nil)", has, err)
	}
	if err := ps.SetPassword(ctx, "alice", "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if has, err := ps.HasPassword(ctx, "alice"); err != nil || !has {
		t.Fatalf("HasPassword after SetPassword = (%v, %v), want (true, nil)", has, err)
	}
	// A different, never-set user still reads as false.
	if has, err := ps.HasPassword(ctx, "bob"); err != nil || has {
		t.Fatalf("HasPassword for unrelated user = (%v, %v), want (false, nil)", has, err)
	}
}

// TestSQLitePasswordStore_ParityWithMemory asserts the SQLite peer is
// behaviorally indistinguishable from the in-memory peer for the contract
// surface that matters: set/verify match, wrong-password mismatch, and
// unknown-user mismatch all collapse to the same observable outcomes.
func TestSQLitePasswordStore_ParityWithMemory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mem := defaultimpl.NewMemoryPasswordCredentialStore()
	sq := newTestPasswordStore(t)

	stores := map[string]sso.PasswordCredentialStore{"memory": mem, "sqlite": sq}
	for name, st := range stores {
		if err := st.SetPassword(ctx, "alice", "shared-secret"); err != nil {
			t.Fatalf("%s SetPassword: %v", name, err)
		}
		if err := st.VerifyPassword(ctx, "alice", "shared-secret"); err != nil {
			t.Fatalf("%s match: %v", name, err)
		}
		if err := st.VerifyPassword(ctx, "alice", "bad"); !errors.Is(err, core.ErrPasswordMismatch) {
			t.Fatalf("%s wrong pw: got %v, want ErrPasswordMismatch", name, err)
		}
		if err := st.VerifyPassword(ctx, "ghost", "bad"); !errors.Is(err, core.ErrPasswordMismatch) {
			t.Fatalf("%s unknown user: got %v, want ErrPasswordMismatch", name, err)
		}
	}
}

// TestSQLitePasswordStore_PasswordChangedAt_UnknownUser confirms an unstamped
// user returns an error (not a zero time treated as "always expired") — the
// login-time expiry gate (interfaces/sso rejectExpiredPassword) relies on
// this to fail open when it can't determine an age.
func TestSQLitePasswordStore_PasswordChangedAt_UnknownUser(t *testing.T) {
	t.Parallel()
	ps := newTestPasswordStore(t)
	if _, err := ps.PasswordChangedAt(context.Background(), "nobody"); err == nil {
		t.Fatalf("PasswordChangedAt: want error for unknown user, got nil")
	}
}

// TestSQLitePasswordStore_PasswordChangedAt_StampedOnSet confirms SetPassword
// stamps updated_at (read back via PasswordChangedAt) within a tight
// tolerance of "now" — no schema migration needed, the column already
// existed; this is a read-accessor-only addition.
func TestSQLitePasswordStore_PasswordChangedAt_StampedOnSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ps := newTestPasswordStore(t)

	before := time.Now()
	if err := ps.SetPassword(ctx, "alice", "first-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	after := time.Now()

	got, err := ps.PasswordChangedAt(ctx, "alice")
	if err != nil {
		t.Fatalf("PasswordChangedAt: %v", err)
	}
	if got.Before(before) || got.After(after) {
		t.Fatalf("PasswordChangedAt = %v; want between %v and %v", got, before, after)
	}
}

// TestSQLitePasswordStore_PasswordChangedAt_UpdatedOnChange confirms a
// SUBSEQUENT SetPassword call (self-service change / admin reset) re-stamps
// updated_at to the new time, resetting the age clock.
func TestSQLitePasswordStore_PasswordChangedAt_UpdatedOnChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ps := newTestPasswordStore(t)

	if err := ps.SetPassword(ctx, "alice", "first-password"); err != nil {
		t.Fatalf("SetPassword (first): %v", err)
	}
	first, err := ps.PasswordChangedAt(ctx, "alice")
	if err != nil {
		t.Fatalf("PasswordChangedAt (first): %v", err)
	}

	time.Sleep(2 * time.Millisecond)

	if err := ps.SetPassword(ctx, "alice", "second-password"); err != nil {
		t.Fatalf("SetPassword (second): %v", err)
	}
	second, err := ps.PasswordChangedAt(ctx, "alice")
	if err != nil {
		t.Fatalf("PasswordChangedAt (second): %v", err)
	}
	if !second.After(first) {
		t.Fatalf("PasswordChangedAt did not advance on change: first=%v second=%v", first, second)
	}
}
