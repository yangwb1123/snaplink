package memorystorecredential

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

func TestMemoryTrustedDeviceStore_TrustThenVerify(t *testing.T) {
	s := NewMemoryTrustedDeviceStore()
	token, dev, err := s.Trust(context.Background(), "alice", "client-a", "Chrome on macOS", time.Hour)
	if err != nil {
		t.Fatalf("trust: %v", err)
	}
	if token == "" {
		t.Fatal("empty token returned")
	}
	if dev == nil || dev.ID == "" {
		t.Fatalf("no device record returned: %+v", dev)
	}
	if dev.UserID != "alice" || dev.ClientID != "client-a" || dev.Label != "Chrome on macOS" {
		t.Fatalf("device record mismatch: %+v", dev)
	}

	ok, err := s.Verify(context.Background(), "alice", "client-a", token)
	if err != nil || !ok {
		t.Fatalf("verify = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestMemoryTrustedDeviceStore_PlaintextNotStored proves the store never
// keeps a usable copy of the token — only its SHA-256 hash — mirroring the
// RecoveryCodeStore contract. Internal test so it can read the unexported map.
func TestMemoryTrustedDeviceStore_PlaintextNotStored(t *testing.T) {
	s := NewMemoryTrustedDeviceStore()
	token, dev, _ := s.Trust(context.Background(), "alice", "client-a", "", time.Hour)
	rec := s.devices["alice"][dev.ID]
	if rec == nil {
		t.Fatal("record not found")
	}
	if rec.hash == token {
		t.Fatalf("stored hash equals the plaintext token — hashing not applied")
	}
	if len(rec.hash) != 64 { // SHA-256 hex digest length
		t.Fatalf("stored hash %q is %d chars, want a 64-char SHA-256 hex digest", rec.hash, len(rec.hash))
	}
}

func TestMemoryTrustedDeviceStore_VerifyScopedToUserAndClient(t *testing.T) {
	s := NewMemoryTrustedDeviceStore()
	token, _, _ := s.Trust(context.Background(), "alice", "client-a", "", time.Hour)

	cases := []struct {
		name     string
		user     string
		clientID string
		token    string
		want     bool
	}{
		{"exact match", "alice", "client-a", token, true},
		{"wrong client", "alice", "client-b", token, false},
		{"wrong user", "mallory", "client-a", token, false},
		{"garbage token", "alice", "client-a", "not-a-real-token", false},
		{"empty token", "alice", "client-a", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := s.Verify(context.Background(), tc.user, tc.clientID, tc.token)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if ok != tc.want {
				t.Errorf("verify(%s, %s) = %v, want %v", tc.user, tc.clientID, ok, tc.want)
			}
		})
	}
}

func TestMemoryTrustedDeviceStore_VerifyRejectsExpired(t *testing.T) {
	s := NewMemoryTrustedDeviceStore()
	token, _, _ := s.Trust(context.Background(), "alice", "client-a", "", time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	ok, err := s.Verify(context.Background(), "alice", "client-a", token)
	if err != nil || ok {
		t.Fatalf("verify expired = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestMemoryTrustedDeviceStore_TrustDefaultsTTL(t *testing.T) {
	s := NewMemoryTrustedDeviceStore()
	_, dev, err := s.Trust(context.Background(), "alice", "client-a", "", 0)
	if err != nil {
		t.Fatalf("trust: %v", err)
	}
	want := dev.CreatedAt.Add(core.DefaultTrustedDeviceTTL)
	if dev.ExpiresAt.Before(want.Add(-time.Second)) || dev.ExpiresAt.After(want.Add(time.Second)) {
		t.Errorf("ExpiresAt = %v, want ~%v (DefaultTrustedDeviceTTL applied)", dev.ExpiresAt, want)
	}
}

func TestMemoryTrustedDeviceStore_ListByUserOmitsTokenAndOtherUsers(t *testing.T) {
	s := NewMemoryTrustedDeviceStore()
	_, _, _ = s.Trust(context.Background(), "alice", "client-a", "phone", time.Hour)
	_, _, _ = s.Trust(context.Background(), "alice", "client-b", "laptop", time.Hour)
	_, _, _ = s.Trust(context.Background(), "mallory", "client-a", "other", time.Hour)

	devices, err := s.ListByUser(context.Background(), "alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2", len(devices))
	}
	for _, d := range devices {
		if d.UserID != "alice" {
			t.Errorf("leaked another user's device: %+v", d)
		}
	}
}

func TestMemoryTrustedDeviceStore_RevokeIsOwnershipScopedAndIdempotent(t *testing.T) {
	s := NewMemoryTrustedDeviceStore()
	token, dev, _ := s.Trust(context.Background(), "alice", "client-a", "", time.Hour)

	// Cross-user revoke touches nothing.
	if err := s.Revoke(context.Background(), "mallory", dev.ID); err != nil {
		t.Fatalf("cross-user revoke: %v", err)
	}
	if ok, _ := s.Verify(context.Background(), "alice", "client-a", token); !ok {
		t.Fatal("cross-user revoke removed alice's device")
	}

	// Owner revoke removes it.
	if err := s.Revoke(context.Background(), "alice", dev.ID); err != nil {
		t.Fatalf("owner revoke: %v", err)
	}
	if ok, _ := s.Verify(context.Background(), "alice", "client-a", token); ok {
		t.Fatal("device still verifies after revoke")
	}

	// Idempotent: revoking again (or an unknown id) is a no-op, not an error.
	if err := s.Revoke(context.Background(), "alice", dev.ID); err != nil {
		t.Fatalf("repeat revoke: %v", err)
	}
	if err := s.Revoke(context.Background(), "alice", "no-such-id"); err != nil {
		t.Fatalf("revoke unknown id: %v", err)
	}
}

func TestMemoryTrustedDeviceStore_RevokeAll(t *testing.T) {
	s := NewMemoryTrustedDeviceStore()
	tokenA, _, _ := s.Trust(context.Background(), "alice", "client-a", "", time.Hour)
	tokenB, _, _ := s.Trust(context.Background(), "alice", "client-b", "", time.Hour)
	otherToken, _, _ := s.Trust(context.Background(), "mallory", "client-a", "", time.Hour)

	n, err := s.RevokeAll(context.Background(), "alice")
	if err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoke-all count = %d, want 2", n)
	}
	if ok, _ := s.Verify(context.Background(), "alice", "client-a", tokenA); ok {
		t.Error("tokenA still verifies after revoke-all")
	}
	if ok, _ := s.Verify(context.Background(), "alice", "client-b", tokenB); ok {
		t.Error("tokenB still verifies after revoke-all")
	}
	// A different user's grant is untouched.
	if ok, _ := s.Verify(context.Background(), "mallory", "client-a", otherToken); !ok {
		t.Error("revoke-all for alice touched mallory's grant")
	}

	// Revoking an unknown user is a clean 0, nil.
	if n, err := s.RevokeAll(context.Background(), "nobody"); n != 0 || err != nil {
		t.Fatalf("revoke-all unknown user = (%d, %v), want (0, nil)", n, err)
	}
}

var _ core.TrustedDeviceStore = (*MemoryTrustedDeviceStore)(nil)
