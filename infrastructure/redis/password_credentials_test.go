package redis

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
	"golang.org/x/crypto/bcrypt"
)

func TestRedisPasswordCredentialStore_SetVerifyRoundTrip(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPasswordCredentialStore(rdb)
	ctx := context.Background()

	if err := s.SetPassword(ctx, "u1", "correct horse battery staple"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "correct horse battery staple"); err != nil {
		t.Errorf("VerifyPassword matching = %v, want nil", err)
	}
}

func TestRedisPasswordCredentialStore_WrongPassword(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPasswordCredentialStore(rdb)
	ctx := context.Background()
	_ = s.SetPassword(ctx, "u1", "right")

	if err := s.VerifyPassword(ctx, "u1", "wrong"); !errors.Is(err, sso.ErrPasswordMismatch) {
		t.Errorf("VerifyPassword wrong = %v, want ErrPasswordMismatch", err)
	}
}

// TestRedisPasswordCredentialStore_UnknownUser verifies the anti-enumeration
// collapse: an unknown user maps to the SAME ErrPasswordMismatch as a wrong
// password, indistinguishable from the caller's side.
func TestRedisPasswordCredentialStore_UnknownUser(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPasswordCredentialStore(rdb)
	if err := s.VerifyPassword(context.Background(), "ghost", "anything"); !errors.Is(err, sso.ErrPasswordMismatch) {
		t.Errorf("VerifyPassword unknown user = %v, want ErrPasswordMismatch", err)
	}
}

func TestRedisPasswordCredentialStore_SetPasswordHash(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPasswordCredentialStore(rdb)
	ctx := context.Background()

	// Rejects a plaintext masquerading as a hash.
	if err := s.SetPasswordHash(ctx, "u1", "not-a-bcrypt-hash"); err == nil {
		t.Errorf("SetPasswordHash(plaintext) = nil, want error")
	}

	// Accepts a real bcrypt hash and verifies against it.
	h, err := bcrypt.GenerateFromPassword([]byte("imported"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := s.SetPasswordHash(ctx, "u1", string(h)); err != nil {
		t.Fatalf("SetPasswordHash(hash) = %v, want nil", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "imported"); err != nil {
		t.Errorf("VerifyPassword after import = %v, want nil", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "wrong"); !errors.Is(err, sso.ErrPasswordMismatch) {
		t.Errorf("VerifyPassword wrong after import = %v, want ErrPasswordMismatch", err)
	}
}

// TestRedisPasswordCredentialStore_SetReplaces verifies a second SetPassword
// overwrites the prior hash (parity with the memory peer's map-write).
func TestRedisPasswordCredentialStore_SetReplaces(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPasswordCredentialStore(rdb)
	ctx := context.Background()

	_ = s.SetPassword(ctx, "u1", "old")
	if err := s.SetPassword(ctx, "u1", "new"); err != nil {
		t.Fatalf("SetPassword replace: %v", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "new"); err != nil {
		t.Errorf("VerifyPassword new = %v, want nil", err)
	}
	if err := s.VerifyPassword(ctx, "u1", "old"); !errors.Is(err, sso.ErrPasswordMismatch) {
		t.Errorf("old password still valid after replace: %v", err)
	}
}

// TestRedisPasswordCredentialStore_EmptyUserID confirms an empty userID is
// rejected on the write side (parity with memory + sqlite peers).
func TestRedisPasswordCredentialStore_EmptyUserID(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPasswordCredentialStore(rdb)
	ctx := context.Background()
	if err := s.SetPassword(ctx, "", "x"); !errors.Is(err, sso.ErrPasswordMismatch) {
		t.Errorf("SetPassword empty id = %v, want ErrPasswordMismatch", err)
	}
	if err := s.SetPasswordHash(ctx, "", "$2a$10$abc"); !errors.Is(err, sso.ErrPasswordMismatch) {
		t.Errorf("SetPasswordHash empty id = %v, want ErrPasswordMismatch", err)
	}
}
