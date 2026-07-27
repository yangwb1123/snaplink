package sqlite_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
)

func newTOTPEnrollStore(t *testing.T) *sqlitestores.TOTPEnrollmentStore {
	t.Helper()
	dsn := "file:totpenr_" + t.Name() + "?mode=memory&cache=shared&_pragma=busy_timeout(5000)"
	s, err := sqlitestores.NewTOTPEnrollmentStore(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteTOTPEnrollmentStore_Lifecycle(t *testing.T) {
	t.Parallel()
	s := newTOTPEnrollStore(t)
	ctx := context.Background()
	secret := []byte("seedbytes12345678901")

	if fs, _ := s.ListFactors(ctx, "u-alice"); len(fs) != 0 {
		t.Fatalf("ListFactors before enroll = %d, want 0", len(fs))
	}
	if _, err := s.GetSecret(ctx, "u-alice"); !errors.Is(err, authenticators.ErrTOTPNoSecret) {
		t.Errorf("GetSecret before enroll err=%v, want ErrTOTPNoSecret", err)
	}

	if err := s.AddTOTPFactor(ctx, "u-alice", "f1", "iPhone", secret); err != nil {
		t.Fatalf("AddTOTPFactor: %v", err)
	}
	fs, _ := s.ListFactors(ctx, "u-alice")
	if len(fs) != 1 || fs[0].ID != "f1" || fs[0].Method != authenticators.MethodTOTP || fs[0].Label != "iPhone" {
		t.Fatalf("ListFactors = %+v", fs)
	}
	if fs[0].AddedAt.IsZero() {
		t.Error("AddedAt not set on enrolled factor")
	}
	if got, err := s.GetSecret(ctx, "u-alice"); err != nil || string(got) != string(secret) {
		t.Fatalf("GetSecret = %q,%v; want %q", got, err, secret)
	}

	// Re-enroll REPLACES the prior factor + secret (one TOTP per user).
	secret2 := []byte("differentbytes098765")
	if err := s.AddTOTPFactor(ctx, "u-alice", "f2", "Tablet", secret2); err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if fs, _ := s.ListFactors(ctx, "u-alice"); len(fs) != 1 || fs[0].ID != "f2" {
		t.Fatalf("re-enroll did not replace: %+v", fs)
	}
	if got2, _ := s.GetSecret(ctx, "u-alice"); string(got2) != string(secret2) {
		t.Error("re-enroll did not replace the secret")
	}

	// A non-matching factorID is a no-op.
	_ = s.RemoveFactor(ctx, "u-alice", "wrong-id")
	if fs, _ := s.ListFactors(ctx, "u-alice"); len(fs) != 1 {
		t.Error("RemoveFactor with a wrong id should be a no-op")
	}

	// Removing the real factor clears both the factor and the secret.
	if err := s.RemoveFactor(ctx, "u-alice", "f2"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if fs, _ := s.ListFactors(ctx, "u-alice"); len(fs) != 0 {
		t.Error("RemoveFactor did not remove the factor")
	}
	if _, err := s.GetSecret(ctx, "u-alice"); !errors.Is(err, authenticators.ErrTOTPNoSecret) {
		t.Errorf("GetSecret after remove err=%v, want ErrTOTPNoSecret", err)
	}

	// Per-user isolation: another user's factor is independent.
	_ = s.AddTOTPFactor(ctx, "u-bob", "fb", "Bob phone", secret)
	if got, err := s.GetSecret(ctx, "u-bob"); err != nil || string(got) != string(secret) {
		t.Errorf("bob secret = %q,%v", got, err)
	}
	if fs, _ := s.ListFactors(ctx, "u-alice"); len(fs) != 0 {
		t.Error("alice gained a factor from bob's enrollment")
	}
}
