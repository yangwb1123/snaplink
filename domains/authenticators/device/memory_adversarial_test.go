package device

import (
	"context"
	"sync"
	"testing"
)

func TestMemoryStore_Adversarial_ConcurrentUpsert(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			d := &Device{
				UserID:      "user-1",
				Fingerprint: "fp-1",
				Type:        DeviceTypeBrowser,
				LastIP:      "192.168.1.1",
				TrustScore:  float64(n) / float64(goroutines),
			}
			_ = s.Upsert(ctx, d)
		}(i)
	}
	wg.Wait()

	// After concurrent upserts, there should be exactly 1 device
	devices, err := s.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device after concurrent upsert, got %d", len(devices))
	}
	if devices[0].LoginCount <= 1 {
		t.Errorf("login_count should be >1 after %d concurrent upserts, got %d", goroutines, devices[0].LoginCount)
	}
}

func TestMemoryStore_Adversarial_ConcurrentDifferentUsers(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	const users = 10
	const devicesPerUser = 5
	var wg sync.WaitGroup
	wg.Add(users * devicesPerUser)

	for u := range users {
		for d := range devicesPerUser {
			go func(uid, did int) {
				defer wg.Done()
				_ = s.Upsert(ctx, &Device{
					UserID:      "u-" + itoa(uid),
					Fingerprint: "fp-" + itoa(did),
					Type:        DeviceTypeMobile,
					LastIP:      "10.0.0.1",
				})
			}(u, d)
		}
	}
	wg.Wait()

	for u := range users {
		devices, err := s.ListByUser(ctx, "u-"+itoa(u))
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(devices) != devicesPerUser {
			t.Errorf("user u-%d: expected %d devices, got %d", u, devicesPerUser, len(devices))
		}
	}

	// ListAll should have users * devicesPerUser entries
	all, err := s.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	expected := users * devicesPerUser
	if len(all) != expected {
		t.Errorf("ListAll: expected %d devices, got %d", expected, len(all))
	}
}

func TestMemoryStore_Adversarial_RaceDeleteDuringList(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Seed devices
	for i := range 100 {
		_ = s.Upsert(ctx, &Device{
			UserID:      "user-r",
			Fingerprint: "fp-r" + itoa(i),
			Type:        DeviceTypeDesktop,
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: list repeatedly
	go func() {
		defer wg.Done()
		for range 50 {
			_, _ = s.ListByUser(ctx, "user-r")
			_, _ = s.ListAll(ctx)
		}
	}()

	// Goroutine 2: delete some devices concurrently
	go func() {
		defer wg.Done()
		devices, _ := s.ListByUser(ctx, "user-r")
		for i, d := range devices {
			if i%2 == 0 {
				_ = s.Delete(ctx, d.ID)
			}
		}
	}()

	wg.Wait()
}

func TestMemoryStore_Adversarial_UpsertAfterDeleteReusesSlot(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Create device
	d := &Device{
		UserID:      "user-ad",
		Fingerprint: "fp-ad",
		Type:        DeviceTypeBrowser,
	}
	if err := s.Upsert(ctx, d); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	id1 := d.ID

	// Delete
	if err := s.Delete(ctx, id1); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Re-create same fingerprint — should get new ID, not reuse old one
	d2 := &Device{
		UserID:      "user-ad",
		Fingerprint: "fp-ad",
		Type:        DeviceTypeBrowser,
	}
	if err := s.Upsert(ctx, d2); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if d2.ID == id1 {
		t.Errorf("re-created device should get new ID, not reuse %s", id1)
	}

	// Should have exactly 1 device now
	devices, _ := s.ListByUser(ctx, "user-ad")
	if len(devices) != 1 {
		t.Errorf("expected 1 device after delete+re-create, got %d", len(devices))
	}
}

func TestMemoryStore_Adversarial_GetByFingerprintConsistency(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Upsert same fingerprint multiple times — GetByFingerprint should
	// always return the LATEST device.
	var lastID string
	for i := range 10 {
		d := &Device{
			UserID:      "user-c",
			Fingerprint: "fp-c",
			Type:        DeviceTypeBrowser,
			DeviceName:  "Device v" + itoa(i),
			TrustScore:  float64(i) / 10.0,
		}
		if err := s.Upsert(ctx, d); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
		lastID = d.ID
	}

	got, err := s.GetByFingerprint(ctx, "user-c", "fp-c")
	if err != nil {
		t.Fatalf("GetByFingerprint: %v", err)
	}
	if got.ID != lastID {
		t.Errorf("expected latest ID %s, got %s", lastID, got.ID)
	}
}

func TestMemoryStore_Adversarial_LoginCountStrictMonotonic(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	d := &Device{
		UserID:      "user-m",
		Fingerprint: "fp-m",
		Type:        DeviceTypeDesktop,
		LoginCount:  1,
	}

	prevCount := 0
	for i := range 20 {
		if err := s.Upsert(ctx, d); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
		got, _ := s.GetByFingerprint(ctx, "user-m", "fp-m")
		if got.LoginCount <= prevCount {
			t.Errorf("upsert %d: login_count %d not > prev %d", i, got.LoginCount, prevCount)
		}
		prevCount = got.LoginCount
	}

	if prevCount != 20 {
		t.Errorf("expected login_count=20 after 20 upserts, got %d", prevCount)
	}
}

func TestMemoryStore_Adversarial_DeleteByUserAllGone(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Seed devices for two users
	for i := range 5 {
		_ = s.Upsert(ctx, &Device{
			UserID:      "user-a",
			Fingerprint: "fp-a" + itoa(i),
			Type:        DeviceTypeMobile,
		})
		_ = s.Upsert(ctx, &Device{
			UserID:      "user-b",
			Fingerprint: "fp-b" + itoa(i),
			Type:        DeviceTypeDesktop,
		})
	}

	// Delete user-a
	if err := s.DeleteByUser(ctx, "user-a"); err != nil {
		t.Fatalf("DeleteByUser: %v", err)
	}

	// User-a should have 0 devices
	devsA, _ := s.ListByUser(ctx, "user-a")
	if len(devsA) != 0 {
		t.Errorf("user-a: expected 0 devices after delete, got %d", len(devsA))
	}

	// User-b should still have 5
	devsB, _ := s.ListByUser(ctx, "user-b")
	if len(devsB) != 5 {
		t.Errorf("user-b: expected 5 devices, got %d", len(devsB))
	}
}

func TestMemoryStore_Adversarial_NilContext(t *testing.T) {
	s := NewMemoryStore()

	// All operations must tolerate nil context without panicking.
	_ = s.Upsert(nil, &Device{UserID: "u", Fingerprint: "fp", Type: DeviceTypeBrowser})
	_, _ = s.GetByFingerprint(nil, "u", "fp")
	_, _ = s.ListByUser(nil, "u")
	_, _ = s.ListAll(nil)
	_ = s.Delete(nil, "nonexistent")
	_ = s.DeleteByUser(nil, "u")
}

// itoa is a minimal int→string for test helpers (avoid strconv import).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
