package device

import (
	"context"
	"testing"
)

func TestMemoryStore_UpsertAndGet(t *testing.T) {
	s := NewMemoryStore()
	d := &Device{
		UserID:      "user1",
		Fingerprint: "fp_abc123",
		Type:        DeviceTypeMobile,
		Platform:    "iOS",
		DeviceName:  "iPhone",
	}
	if err := s.Upsert(context.Background(), d); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if d.ID == "" {
		t.Fatal("ID should be set after Upsert")
	}

	got, err := s.Get(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Fingerprint != "fp_abc123" {
		t.Errorf("Fingerprint = %q", got.Fingerprint)
	}
	if got.FirstSeenAt.IsZero() {
		t.Error("FirstSeenAt is zero")
	}
}

func TestMemoryStore_GetByFingerprint(t *testing.T) {
	s := NewMemoryStore()
	d := &Device{UserID: "user1", Fingerprint: "fp_xyz"}
	_ = s.Upsert(context.Background(), d)

	got, err := s.GetByFingerprint(context.Background(), "user1", "fp_xyz")
	if err != nil {
		t.Fatalf("GetByFingerprint: %v", err)
	}
	if got.ID != d.ID {
		t.Errorf("ID = %q, want %q", got.ID, d.ID)
	}
}

func TestMemoryStore_GetByFingerprint_NotFound(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.GetByFingerprint(context.Background(), "user1", "nonexistent")
	if err != ErrNoSuchDevice {
		t.Errorf("err = %v, want ErrNoSuchDevice", err)
	}
}

func TestMemoryStore_UpsertUpdatesExisting(t *testing.T) {
	s := NewMemoryStore()
	d := &Device{UserID: "user1", Fingerprint: "fp_abc", Platform: "iOS"}
	_ = s.Upsert(context.Background(), d)

	d.Platform = "Android"
	_ = s.Upsert(context.Background(), d)

	got, _ := s.GetByFingerprint(context.Background(), "user1", "fp_abc")
	if got.Platform != "Android" {
		t.Errorf("Platform = %q, want Android (updated)", got.Platform)
	}
}

func TestMemoryStore_ListByUser(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Upsert(context.Background(), &Device{UserID: "user1", Fingerprint: "fp_1"})
	_ = s.Upsert(context.Background(), &Device{UserID: "user1", Fingerprint: "fp_2"})
	_ = s.Upsert(context.Background(), &Device{UserID: "user2", Fingerprint: "fp_3"})

	devices, err := s.ListByUser(context.Background(), "user1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(devices) != 2 {
		t.Errorf("expected 2 devices, got %d", len(devices))
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	s := NewMemoryStore()
	d := &Device{UserID: "user1", Fingerprint: "fp_del"}
	_ = s.Upsert(context.Background(), d)

	if err := s.Delete(context.Background(), d.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := s.Get(context.Background(), d.ID)
	if err != ErrNoSuchDevice {
		t.Error("expected ErrNoSuchDevice after delete")
	}
}

func TestMemoryStore_DeleteIdempotent(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Delete(context.Background(), "nonexistent"); err != nil {
		t.Errorf("delete absent: %v", err)
	}
}

func TestMemoryStore_DeleteByUser(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Upsert(context.Background(), &Device{UserID: "user1", Fingerprint: "fp_a"})
	_ = s.Upsert(context.Background(), &Device{UserID: "user1", Fingerprint: "fp_b"})
	_ = s.Upsert(context.Background(), &Device{UserID: "user2", Fingerprint: "fp_c"})

	if err := s.DeleteByUser(context.Background(), "user1"); err != nil {
		t.Fatalf("DeleteByUser: %v", err)
	}
	devices, _ := s.ListByUser(context.Background(), "user1")
	if len(devices) != 0 {
		t.Errorf("expected 0 devices for user1 after DeleteByUser, got %d", len(devices))
	}
	// user2 should still have their device.
	devices2, _ := s.ListByUser(context.Background(), "user2")
	if len(devices2) != 1 {
		t.Errorf("expected 1 device for user2, got %d", len(devices2))
	}
}

func TestMemoryStore_ListByUser_Empty(t *testing.T) {
	s := NewMemoryStore()
	devices, err := s.ListByUser(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("expected 0 devices, got %d", len(devices))
	}
}

func TestMemoryStore_CloneIsIndependent(t *testing.T) {
	s := NewMemoryStore()
	d := &Device{UserID: "u1", Fingerprint: "fp_clone", Platform: "iOS"}
	_ = s.Upsert(context.Background(), d)

	got, _ := s.Get(context.Background(), d.ID)
	got.Platform = "hacked"

	got2, _ := s.Get(context.Background(), d.ID)
	if got2.Platform == "hacked" {
		t.Error("Clone did not protect original")
	}
}
