package defaultimpl

import (
	"context"
	"encoding/base64"
	"testing"

	gw "github.com/go-webauthn/webauthn/webauthn"
	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators/webauthn"
)

func seedPasskeys(t *testing.T, userID string, credIDs ...string) *webauthn.MemoryUserStore {
	t.Helper()
	us := webauthn.NewMemoryUserStore()
	ctx := context.Background()
	if _, err := us.CreateUser(ctx, userID, userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for _, id := range credIDs {
		if err := us.AddCredential(ctx, userID, &gw.Credential{ID: []byte(id)}); err != nil {
			t.Fatalf("AddCredential %q: %v", id, err)
		}
	}
	return us
}

func TestWebAuthnMFAAdapter_ListAndRemove(t *testing.T) {
	ctx := context.Background()
	us := seedPasskeys(t, "u-alice", "credA", "credB")
	a := NewWebAuthnMFAEnrollmentAdapter(us)

	factors, err := a.ListFactors(ctx, "u-alice")
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(factors) != 2 {
		t.Fatalf("want 2 passkey factors, got %+v", factors)
	}
	for _, f := range factors {
		if f.Method != webauthn.MethodWebAuthn {
			t.Errorf("factor method = %q, want webauthn", f.Method)
		}
	}

	// Unknown user → empty, not error.
	if fs, err := a.ListFactors(ctx, "nobody"); err != nil || len(fs) != 0 {
		t.Errorf("unknown user ListFactors = %v, %v; want empty,nil", fs, err)
	}

	// Remove credA by its base64url factor id.
	idA := base64.RawURLEncoding.EncodeToString([]byte("credA"))
	if err := a.RemoveFactor(ctx, "u-alice", idA); err != nil {
		t.Fatalf("RemoveFactor: %v", err)
	}
	left, _ := a.ListFactors(ctx, "u-alice")
	if len(left) != 1 || left[0].ID != base64.RawURLEncoding.EncodeToString([]byte("credB")) {
		t.Fatalf("after remove = %+v, want only credB", left)
	}

	// A non-decodable / non-webauthn factor id is a no-op (composite routing).
	if err := a.RemoveFactor(ctx, "u-alice", "totp-not-base64-!!!"); err != nil {
		t.Errorf("non-webauthn id should be a no-op, got %v", err)
	}
	if fs, _ := a.ListFactors(ctx, "u-alice"); len(fs) != 1 {
		t.Errorf("no-op remove changed the set: %+v", fs)
	}

	// Unknown user remove is a no-op.
	if err := a.RemoveFactor(ctx, "nobody", idA); err != nil {
		t.Errorf("unknown user remove = %v, want nil", err)
	}
}

func TestCompositeMFA_FanOutAndRouting(t *testing.T) {
	ctx := context.Background()
	totp := NewMemoryTOTPEnrollmentStore()
	_ = totp.AddTOTPFactor(ctx, "u-alice", "totp-1", "Phone", []byte("secret-bytes-1234567"))
	wa := NewWebAuthnMFAEnrollmentAdapter(seedPasskeys(t, "u-alice", "credA"))

	comp := NewCompositeMFAEnrollmentStore(totp, wa)

	factors, err := comp.ListFactors(ctx, "u-alice")
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(factors) != 2 {
		t.Fatalf("want totp + passkey, got %+v", factors)
	}

	// Removing the TOTP factor leaves the passkey (routed to the right delegate).
	if err := comp.RemoveFactor(ctx, "u-alice", "totp-1"); err != nil {
		t.Fatalf("remove totp: %v", err)
	}
	left, _ := comp.ListFactors(ctx, "u-alice")
	if len(left) != 1 || left[0].Method != webauthn.MethodWebAuthn {
		t.Fatalf("after totp remove = %+v, want only the passkey", left)
	}

	// Removing the passkey leaves nothing.
	if err := comp.RemoveFactor(ctx, "u-alice", base64.RawURLEncoding.EncodeToString([]byte("credA"))); err != nil {
		t.Fatalf("remove passkey: %v", err)
	}
	if fs, _ := comp.ListFactors(ctx, "u-alice"); len(fs) != 0 {
		t.Fatalf("after both removed = %+v, want empty", fs)
	}
}

func TestCompositeMFA_ForwardsTOTPEnrollmentWriter(t *testing.T) {
	wa := NewWebAuthnMFAEnrollmentAdapter(seedPasskeys(t, "u-alice", "credA"))
	totp := NewMemoryTOTPEnrollmentStore()

	// With a TOTP-writer delegate, the composite MUST satisfy TOTPEnrollmentWriter
	// so the /me/mfa/totp routes still mount.
	withTOTP := NewCompositeMFAEnrollmentStore(wa, totp)
	w, ok := withTOTP.(sso.TOTPEnrollmentWriter)
	if !ok {
		t.Fatal("composite with a TOTP-writer delegate must satisfy TOTPEnrollmentWriter")
	}
	if err := w.AddTOTPFactor(context.Background(), "u-bob", "f1", "lbl", []byte("s")); err != nil {
		t.Fatalf("forwarded AddTOTPFactor: %v", err)
	}
	if got, _ := totp.GetSecret(context.Background(), "u-bob"); string(got) != "s" {
		t.Error("forwarded AddTOTPFactor did not reach the TOTP delegate")
	}

	// Without a writer delegate, the composite MUST NOT satisfy it (routes stay off).
	if _, ok := NewCompositeMFAEnrollmentStore(wa).(sso.TOTPEnrollmentWriter); ok {
		t.Error("composite with no writer delegate must NOT satisfy TOTPEnrollmentWriter")
	}
}
