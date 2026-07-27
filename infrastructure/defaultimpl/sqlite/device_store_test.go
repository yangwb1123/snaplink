package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
)

func deviceDSN(t *testing.T) string {
	t.Helper()
	return "file:" + filepath.Join(t.TempDir(), "device.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
}

func TestSQLiteDeviceStore_UpsertAndGet(t *testing.T) {
	ctx := context.Background()

	store, err := NewDeviceStore(deviceDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	d := &device.Device{
		UserID:      "test-user",
		Fingerprint: "test-fp-1",
		Type:        device.DeviceTypeDesktop,
		Platform:    "Linux",
		DeviceName:  "Test Machine",
		LastIP:      "192.168.1.1",
		TrustScore:  0.75,
	}

	if err := store.Upsert(ctx, d); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if d.ID == "" {
		t.Fatal("Upsert should set ID on input")
	}

	got, err := store.Get(ctx, d.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UserID != "test-user" {
		t.Errorf("expected UserID 'test-user', got '%s'", got.UserID)
	}
	if got.Fingerprint != "test-fp-1" {
		t.Errorf("expected Fingerprint 'test-fp-1', got '%s'", got.Fingerprint)
	}
	if string(got.Type) != "desktop" {
		t.Errorf("expected Type 'desktop', got '%s'", string(got.Type))
	}
}

func TestSQLiteDeviceStore_GetByFingerprint(t *testing.T) {
	ctx := context.Background()

	store, err := NewDeviceStore(deviceDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	d := &device.Device{
		UserID:      "test-user",
		Fingerprint: "unique-fp",
		Type:        device.DeviceTypeMobile,
		Platform:    "iOS",
	}
	if err := store.Upsert(ctx, d); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := store.GetByFingerprint(ctx, "test-user", "unique-fp")
	if err != nil {
		t.Fatalf("GetByFingerprint: %v", err)
	}
	if got.Fingerprint != "unique-fp" {
		t.Errorf("expected fingerprint 'unique-fp', got '%s'", got.Fingerprint)
	}
}

func TestSQLiteDeviceStore_GetByFingerprintNotFound(t *testing.T) {
	ctx := context.Background()

	store, err := NewDeviceStore(deviceDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_, err = store.GetByFingerprint(ctx, "nonexistent", "nope")
	if err != device.ErrNoSuchDevice {
		t.Errorf("expected ErrNoSuchDevice, got %v", err)
	}
}

func TestSQLiteDeviceStore_ListByUser(t *testing.T) {
	ctx := context.Background()

	store, err := NewDeviceStore(deviceDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	for i := 0; i < 3; i++ {
		_ = store.Upsert(ctx, &device.Device{
			UserID:      "list-user",
			Fingerprint: "fp-" + itoa(i),
			Type:        device.DeviceTypeMobile,
		})
	}

	devices, err := store.ListByUser(ctx, "list-user")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(devices) != 3 {
		t.Errorf("expected 3 devices, got %d", len(devices))
	}
}

func TestSQLiteDeviceStore_Delete(t *testing.T) {
	ctx := context.Background()

	store, err := NewDeviceStore(deviceDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	d := &device.Device{
		UserID:      "del-user",
		Fingerprint: "del-fp",
		Type:        device.DeviceTypeDesktop,
	}
	if err := store.Upsert(ctx, d); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := store.Delete(ctx, d.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = store.Get(ctx, d.ID)
	if err != device.ErrNoSuchDevice {
		t.Errorf("expected ErrNoSuchDevice after delete, got %v", err)
	}
}

func TestSQLiteDeviceStore_DeleteByUser(t *testing.T) {
	ctx := context.Background()

	store, err := NewDeviceStore(deviceDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	for i := 0; i < 5; i++ {
		_ = store.Upsert(ctx, &device.Device{
			UserID:      "user-del",
			Fingerprint: "fp-del-" + itoa(i),
		})
	}

	if err := store.DeleteByUser(ctx, "user-del"); err != nil {
		t.Fatalf("DeleteByUser: %v", err)
	}

	devices, _ := store.ListByUser(ctx, "user-del")
	if len(devices) != 0 {
		t.Errorf("expected 0 devices after DeleteByUser, got %d", len(devices))
	}
}

func TestSQLiteDeviceStore_ListAll(t *testing.T) {
	ctx := context.Background()

	store, err := NewDeviceStore(deviceDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	for i := 0; i < 3; i++ {
		_ = store.Upsert(ctx, &device.Device{
			UserID:      "user-" + itoa(i),
			Fingerprint: "fp-" + itoa(i),
		})
	}

	all, err := store.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 devices total, got %d", len(all))
	}
}

func itoa(n int) string {
	if n == 0 { return "0" }
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--; buf[i] = byte('0' + n%10); n /= 10
	}
	return string(buf[i:])
}
