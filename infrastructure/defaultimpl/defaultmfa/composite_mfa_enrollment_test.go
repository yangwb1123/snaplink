package defaultmfa

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// fakeMFAStore is a trivial non-TOTP-writer MFAEnrollmentStore delegate for the
// composite tests — it stands in for the WebAuthn adapter (which lives in
// authenticators/webauthn) so these tests don't pull go-webauthn into
// defaultimpl's test closure.
type fakeMFAStore struct {
	factors map[string][]core.MFAEnrolledFactor
}

func newFakeMFAStore() *fakeMFAStore {
	return &fakeMFAStore{factors: map[string][]core.MFAEnrolledFactor{}}
}

func (f *fakeMFAStore) ListFactors(_ context.Context, userID string) ([]core.MFAEnrolledFactor, error) {
	return f.factors[userID], nil
}

func (f *fakeMFAStore) RemoveFactor(_ context.Context, userID, factorID string) error {
	src := f.factors[userID]
	out := src[:0:0]
	for _, x := range src {
		if x.ID != factorID {
			out = append(out, x)
		}
	}
	f.factors[userID] = out
	return nil
}

func TestCompositeMFA_FanOutAndRouting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	totp := NewMemoryTOTPEnrollmentStore()
	_ = totp.AddTOTPFactor(ctx, "u-alice", "totp-1", "Phone", []byte("secret-bytes-1234567"))
	other := newFakeMFAStore()
	other.factors["u-alice"] = []core.MFAEnrolledFactor{{ID: "wa-1", Method: "webauthn", Label: "Passkey"}}

	comp := NewCompositeMFAEnrollmentStore(totp, other)

	factors, err := comp.ListFactors(ctx, "u-alice")
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(factors) != 2 {
		t.Fatalf("want 2 factors, got %+v", factors)
	}

	// Removing the TOTP factor leaves the other (routed to the owning delegate;
	// the non-owner no-ops per the idempotent RemoveFactor contract).
	if err := comp.RemoveFactor(ctx, "u-alice", "totp-1"); err != nil {
		t.Fatalf("remove totp: %v", err)
	}
	left, _ := comp.ListFactors(ctx, "u-alice")
	if len(left) != 1 || left[0].ID != "wa-1" {
		t.Fatalf("after totp remove = %+v, want only wa-1", left)
	}

	if err := comp.RemoveFactor(ctx, "u-alice", "wa-1"); err != nil {
		t.Fatalf("remove wa: %v", err)
	}
	if fs, _ := comp.ListFactors(ctx, "u-alice"); len(fs) != 0 {
		t.Fatalf("after both removed = %+v, want empty", fs)
	}
}

func TestCompositeMFA_ForwardsTOTPEnrollmentWriter(t *testing.T) {
	t.Parallel()
	totp := NewMemoryTOTPEnrollmentStore()
	other := newFakeMFAStore()

	// With a TOTP-writer delegate, the composite MUST satisfy TOTPEnrollmentWriter
	// so the /me/mfa/totp routes still mount.
	withTOTP := NewCompositeMFAEnrollmentStore(other, totp)
	w, ok := withTOTP.(core.TOTPEnrollmentWriter)
	if !ok {
		t.Fatal("composite with a TOTP-writer delegate must satisfy TOTPEnrollmentWriter")
	}
	if err := w.AddTOTPFactor(context.Background(), "u-bob", "f1", "lbl", []byte("s")); err != nil {
		t.Fatalf("forwarded AddTOTPFactor: %v", err)
	}
	if got, _ := totp.GetSecret(context.Background(), "u-bob"); string(got) != "s" {
		t.Error("forwarded AddTOTPFactor did not reach the TOTP delegate")
	}

	// Without a writer delegate, the composite MUST NOT satisfy it (routes off).
	if _, ok := NewCompositeMFAEnrollmentStore(other).(core.TOTPEnrollmentWriter); ok {
		t.Error("composite with no writer delegate must NOT satisfy TOTPEnrollmentWriter")
	}
}
