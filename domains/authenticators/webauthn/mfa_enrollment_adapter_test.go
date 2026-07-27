package webauthn_test

import (
	"context"
	"encoding/base64"
	"testing"

	gw "github.com/go-webauthn/webauthn/webauthn"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
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

func TestMFAEnrollmentAdapter_ListAndRemove(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := webauthn.NewMFAEnrollmentAdapter(seedPasskeys(t, "u-alice", "credA", "credB"))

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

	// Unknown-user remove is a no-op.
	if err := a.RemoveFactor(ctx, "nobody", idA); err != nil {
		t.Errorf("unknown user remove = %v, want nil", err)
	}
}

// TestMFAEnrollmentAdapter_SurfacesDiscoverable proves that a credProps
// "rk" result captured via SetCredentialExtensions flows through to the
// self-service /me/mfa listing on the matching factor ID ONLY — a sibling
// credential with no captured extension keeps Discoverable nil (unknown),
// never false.
func TestMFAEnrollmentAdapter_SurfacesDiscoverable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	us := seedPasskeys(t, "u-bob", "credX", "credY")

	rk := true
	if err := us.SetCredentialExtensions(ctx, "u-bob", []byte("credX"), webauthn.CredentialExtensions{Discoverable: &rk}); err != nil {
		t.Fatalf("SetCredentialExtensions: %v", err)
	}

	a := webauthn.NewMFAEnrollmentAdapter(us)
	factors, err := a.ListFactors(ctx, "u-bob")
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(factors) != 2 {
		t.Fatalf("want 2 factors, got %+v", factors)
	}
	idX := base64.RawURLEncoding.EncodeToString([]byte("credX"))
	idY := base64.RawURLEncoding.EncodeToString([]byte("credY"))
	for _, f := range factors {
		switch f.ID {
		case idX:
			if f.Discoverable == nil || !*f.Discoverable {
				t.Errorf("credX Discoverable = %v, want true", f.Discoverable)
			}
		case idY:
			if f.Discoverable != nil {
				t.Errorf("credY Discoverable = %v, want nil (never captured)", *f.Discoverable)
			}
		default:
			t.Errorf("unexpected factor id %q", f.ID)
		}
	}
}
