package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
)

func TestMemoryEmailChangeStore_RevokeAndList(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryEmailChangeStore()
	_ = s.Issue(ctx, &core.EmailChangeToken{Token: "t1", UserID: "alice", NewEmail: "a1@e.com", ExpiresAt: time.Now().Add(time.Minute)})
	_ = s.Issue(ctx, &core.EmailChangeToken{Token: "t2", UserID: "alice", NewEmail: "a2@e.com", ExpiresAt: time.Now().Add(time.Minute)})
	_ = s.Issue(ctx, &core.EmailChangeToken{Token: "t3", UserID: "bob", NewEmail: "b@e.com", ExpiresAt: time.Now().Add(time.Minute)})

	list, err := s.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("alice tokens = %d, want 2", len(list))
	}

	n, err := s.RevokeByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("RevokeByUser: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked %d, want 2", n)
	}
	if again, _ := s.ListByUser(ctx, "alice"); len(again) != 0 {
		t.Errorf("alice tokens after revoke = %d, want 0", len(again))
	}
	// bob untouched.
	if bobs, _ := s.ListByUser(ctx, "bob"); len(bobs) != 1 {
		t.Errorf("bob tokens = %d, want 1", len(bobs))
	}
}

func TestMemoryPasswordResetStore_RevokeAndList(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryPasswordResetStore()
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "t1", UserID: "alice", ExpiresAt: time.Now().Add(time.Minute)})
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "t2", UserID: "alice", ExpiresAt: time.Now().Add(time.Minute)})
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "t3", UserID: "bob", ExpiresAt: time.Now().Add(time.Minute)})

	list, err := s.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("alice tokens = %d, want 2", len(list))
	}

	n, err := s.RevokeByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("RevokeByUser: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked %d, want 2", n)
	}
	if again, _ := s.ListByUser(ctx, "alice"); len(again) != 0 {
		t.Errorf("alice tokens after revoke = %d, want 0", len(again))
	}
	if bobs, _ := s.ListByUser(ctx, "bob"); len(bobs) != 1 {
		t.Errorf("bob tokens = %d, want 1", len(bobs))
	}
}

func TestMemoryDeviceSecretStore_RevokeBySubject(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryDeviceSecretStore()
	_ = s.Issue(ctx, &core.DeviceSecret{Secret: "s1", Subject: "alice", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)})
	_ = s.Issue(ctx, &core.DeviceSecret{Secret: "s2", Subject: "alice", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)})
	_ = s.Issue(ctx, &core.DeviceSecret{Secret: "s3", Subject: "bob", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)})

	n, err := s.RevokeBySubject(ctx, "alice")
	if err != nil {
		t.Fatalf("RevokeBySubject: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked %d, want 2", n)
	}
	// bob's binding survives.
	if _, err := s.Consume(ctx, "s3"); err != nil {
		t.Errorf("bob binding destroyed: %v", err)
	}
	// alice's bindings are gone.
	if _, err := s.Consume(ctx, "s1"); err == nil {
		t.Error("alice binding s1 should be revoked")
	}
	// Revoking a subject with no bindings is a no-op.
	if n, _ := s.RevokeBySubject(ctx, "nobody"); n != 0 {
		t.Errorf("RevokeBySubject(nobody) = %d, want 0", n)
	}
}
