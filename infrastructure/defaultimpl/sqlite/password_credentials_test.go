package sqlite_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
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
