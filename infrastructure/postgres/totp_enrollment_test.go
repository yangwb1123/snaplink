package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
)

func freshTOTPEnrollmentStore(t *testing.T) *TOTPEnrollmentStore {
	t.Helper()
	s, err := NewTOTPEnrollmentStore(testConfig(t))
	if err != nil {
		t.Fatalf("NewTOTPEnrollmentStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(), "TRUNCATE totp_factors"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func TestTOTPEnrollment_Lifecycle(t *testing.T) {
	s := freshTOTPEnrollmentStore(t)
	ctx := context.Background()
	secret := []byte("seedbytes12345678901")

	// Empty before enroll: no factors, no secret (ErrTOTPNoSecret sentinel).
	if fs, err := s.ListFactors(ctx, "u-alice"); err != nil || len(fs) != 0 {
		t.Fatalf("ListFactors before enroll = (%v, %v), want (empty, nil)", fs, err)
	}
	if _, err := s.GetSecret(ctx, "u-alice"); !errors.Is(err, authenticators.ErrTOTPNoSecret) {
		t.Errorf("GetSecret before enroll err=%v, want ErrTOTPNoSecret", err)
	}

	if err := s.AddTOTPFactor(ctx, "u-alice", "f1", "iPhone", secret); err != nil {
		t.Fatalf("AddTOTPFactor: %v", err)
	}
	fs, err := s.ListFactors(ctx, "u-alice")
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(fs) != 1 || fs[0].ID != "f1" || fs[0].Method != authenticators.MethodTOTP || fs[0].Label != "iPhone" {
		t.Fatalf("ListFactors = %+v", fs)
	}
	if fs[0].AddedAt.IsZero() {
		t.Error("AddedAt not set on enrolled factor")
	}
	// BYTEA secret round-trips byte-for-byte.
	if got, err := s.GetSecret(ctx, "u-alice"); err != nil || string(got) != string(secret) {
		t.Fatalf("GetSecret = %q,%v; want %q", got, err, secret)
	}
}

func TestTOTPEnrollment_ReEnrollReplacesInFull(t *testing.T) {
	s := freshTOTPEnrollmentStore(t)
	ctx := context.Background()
	secret := []byte("seedbytes12345678901")

	if err := s.AddTOTPFactor(ctx, "u-alice", "f1", "iPhone", secret); err != nil {
		t.Fatalf("AddTOTPFactor: %v", err)
	}

	// Re-enroll REPLACES the prior factor + secret in full (one TOTP per user).
	secret2 := []byte("differentbytes098765")
	if err := s.AddTOTPFactor(ctx, "u-alice", "f2", "Tablet", secret2); err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	fs, err := s.ListFactors(ctx, "u-alice")
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(fs) != 1 || fs[0].ID != "f2" || fs[0].Label != "Tablet" {
		t.Fatalf("re-enroll did not replace factor: %+v", fs)
	}
	if got, _ := s.GetSecret(ctx, "u-alice"); string(got) != string(secret2) {
		t.Error("re-enroll did not replace the secret")
	}
}

func TestTOTPEnrollment_RemoveIsIdempotentAndScoped(t *testing.T) {
	s := freshTOTPEnrollmentStore(t)
	ctx := context.Background()
	secret := []byte("seedbytes12345678901")

	if err := s.AddTOTPFactor(ctx, "u-alice", "f1", "iPhone", secret); err != nil {
		t.Fatalf("AddTOTPFactor: %v", err)
	}

	// A non-matching factorID affects no rows (handler enforces ownership).
	if err := s.RemoveFactor(ctx, "u-alice", "wrong-id"); err != nil {
		t.Fatalf("RemoveFactor(wrong id): %v", err)
	}
	if fs, _ := s.ListFactors(ctx, "u-alice"); len(fs) != 1 {
		t.Fatal("RemoveFactor with a wrong id should be a no-op")
	}

	// Removing the real factor clears both the factor and the secret.
	if err := s.RemoveFactor(ctx, "u-alice", "f1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if fs, _ := s.ListFactors(ctx, "u-alice"); len(fs) != 0 {
		t.Error("RemoveFactor did not remove the factor")
	}
	if _, err := s.GetSecret(ctx, "u-alice"); !errors.Is(err, authenticators.ErrTOTPNoSecret) {
		t.Errorf("GetSecret after remove err=%v, want ErrTOTPNoSecret", err)
	}

	// Idempotent: removing again on an empty row is still nil.
	if err := s.RemoveFactor(ctx, "u-alice", "f1"); err != nil {
		t.Fatalf("RemoveFactor (idempotent): %v", err)
	}
}

func TestTOTPEnrollment_PerUserIsolation(t *testing.T) {
	s := freshTOTPEnrollmentStore(t)
	ctx := context.Background()
	aliceSecret := []byte("aliceseed12345678901")
	bobSecret := []byte("bobseed9876543210abc")

	if err := s.AddTOTPFactor(ctx, "u-alice", "fa", "Alice phone", aliceSecret); err != nil {
		t.Fatalf("AddTOTPFactor alice: %v", err)
	}
	if err := s.AddTOTPFactor(ctx, "u-bob", "fb", "Bob phone", bobSecret); err != nil {
		t.Fatalf("AddTOTPFactor bob: %v", err)
	}

	if got, err := s.GetSecret(ctx, "u-bob"); err != nil || string(got) != string(bobSecret) {
		t.Errorf("bob secret = %q,%v; want %q", got, err, bobSecret)
	}
	// Removing bob's factor must not touch alice's.
	if err := s.RemoveFactor(ctx, "u-bob", "fb"); err != nil {
		t.Fatalf("remove bob: %v", err)
	}
	if got, err := s.GetSecret(ctx, "u-alice"); err != nil || string(got) != string(aliceSecret) {
		t.Errorf("alice secret after bob remove = %q,%v; want %q", got, err, aliceSecret)
	}
}

func TestTOTPEnrollment_AddedAtNanosecondRoundTrip(t *testing.T) {
	s := freshTOTPEnrollmentStore(t)
	ctx := context.Background()

	before := time.Now().UnixNano()
	if err := s.AddTOTPFactor(ctx, "u-ts", "f1", "ts", []byte("seedbytes12345678901")); err != nil {
		t.Fatalf("AddTOTPFactor: %v", err)
	}
	after := time.Now().UnixNano()

	fs, err := s.ListFactors(ctx, "u-ts")
	if err != nil || len(fs) != 1 {
		t.Fatalf("ListFactors = (%v, %v)", fs, err)
	}
	// BIGINT preserves the exact Unix-nanosecond stamp (no timestamptz rounding):
	// the round-tripped value must land within the [before, after] window with
	// full nanosecond fidelity.
	gotNs := fs[0].AddedAt.UnixNano()
	if gotNs < before || gotNs > after {
		t.Fatalf("added_at nanosecond round-trip out of window: got %d, want [%d, %d]", gotNs, before, after)
	}
}
