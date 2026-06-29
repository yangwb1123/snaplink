package defaultimpl_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/shared/core"
	"golang.org/x/crypto/bcrypt"
)

func TestMemoryPasswordCredentialStore_SetAndVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryPasswordCredentialStore()

	if err := s.SetPassword(ctx, "alice", "s3cret!"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := s.VerifyPassword(ctx, "alice", "s3cret!"); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	if err := s.VerifyPassword(ctx, "alice", "wrong"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Errorf("wrong password = %v, want ErrPasswordMismatch", err)
	}
}

func TestMemoryPasswordCredentialStore_UnknownUserMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryPasswordCredentialStore()
	// Anti-enumeration: unknown user collapses to the same mismatch error.
	if err := s.VerifyPassword(ctx, "ghost", "anything"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Errorf("unknown user = %v, want ErrPasswordMismatch", err)
	}
}

func TestMemoryPasswordCredentialStore_EmptyUserRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryPasswordCredentialStore()
	if err := s.SetPassword(ctx, "", "x"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Errorf("SetPassword(empty user) = %v", err)
	}
	if err := s.SetPasswordHash(ctx, "", "$2a$10$abc"); !errors.Is(err, core.ErrPasswordMismatch) {
		t.Errorf("SetPasswordHash(empty user) = %v", err)
	}
}

func TestMemoryPasswordCredentialStore_SetPasswordHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryPasswordCredentialStore()

	h, err := bcrypt.GenerateFromPassword([]byte("imported"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := s.SetPasswordHash(ctx, "bob", string(h)); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	if err := s.VerifyPassword(ctx, "bob", "imported"); err != nil {
		t.Errorf("imported hash verify failed: %v", err)
	}

	// A non-bcrypt value MUST be rejected so plaintext can't masquerade as a hash.
	if err := s.SetPasswordHash(ctx, "carol", "plaintext-not-a-hash"); err == nil {
		t.Error("SetPasswordHash accepted a non-bcrypt value")
	}
}
