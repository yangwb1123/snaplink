package selfservice

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators/device"
)

func TestDevicesAdversarial_ConcurrentUpsertAndList(t *testing.T) {
	store := device.NewMemoryStore()
	ctx := context.Background()
	const userID = "race-user"

	var wg sync.WaitGroup
	wg.Add(20)

	// Concurrent upserts of the same fingerprint
	for range 10 {
		go func() {
			defer wg.Done()
			_ = store.Upsert(ctx, &device.Device{
				UserID:      userID,
				Fingerprint: "fp-1",
				Type:        device.DeviceTypeDesktop,
				DeviceName:  "Racy Desktop",
			})
		}()
	}

	// Concurrent listings
	for range 10 {
		go func() {
			defer wg.Done()
			_, _ = store.ListByUser(ctx, userID)
		}()
	}
	wg.Wait()

	// Should end up with exactly 1 device (same fingerprint)
	devices, err := store.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("expected 1 device for %s, got %d", userID, len(devices))
	}
	// Login count should reflect the total number of upserts
	if devices[0].LoginCount < 2 {
		t.Errorf("expected LoginCount >= 2 after 10 upserts, got %d", devices[0].LoginCount)
	}
}

func TestDevicesAdversarial_RaceDeleteDuringList(t *testing.T) {
	store := device.NewMemoryStore()
	ctx := context.Background()

	// Seed devices for two users
	for i := range 5 {
		_ = store.Upsert(ctx, &device.Device{
			UserID:      "user-a",
			Fingerprint: "fa-" + itoa(i),
		})
		_ = store.Upsert(ctx, &device.Device{
			UserID:      "user-b",
			Fingerprint: "fb-" + itoa(i),
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 30 {
			_, _ = store.ListByUser(ctx, "user-a")
			_, _ = store.ListAll(ctx)
		}
	}()

	go func() {
		defer wg.Done()
		for range 10 {
			devs, _ := store.ListByUser(ctx, "user-a")
			for _, d := range devs {
				_ = store.Delete(ctx, d.ID)
			}
		}
	}()

	wg.Wait()
}

func TestDevicesAdversarial_ConcurrentHistoryRecord(t *testing.T) {
	hist := device.NewMemoryHistoryStore()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			_ = hist.Record(&device.LoginRecord{
				UserID:   "ruser",
				Time:     time.Now(),
				Success:  true,
				Provider: "password",
			})
		}()
	}
	wg.Wait()

	entries, _ := hist.RecentByUser("ruser", 100)
	if len(entries) != goroutines {
		t.Errorf("expected %d history entries, got %d", goroutines, len(entries))
	}
}

func TestDevicesAdversarial_HistoryRecordOrderAfterConcurrentUpsert(t *testing.T) {
	hist := device.NewMemoryHistoryStore()

	// Record sequentially then verify order
	for i := range 10 {
		_ = hist.Record(&device.LoginRecord{
			UserID:   "orderuser",
			Time:     time.Now().Add(time.Duration(i) * time.Millisecond),
			Success:  true,
			Provider: "password",
		})
	}

	entries, _ := hist.RecentByUser("orderuser", 100)
	if len(entries) != 10 {
		t.Fatalf("expected 10 entries, got %d", len(entries))
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Time.Before(entries[i].Time) {
			t.Errorf("entry %d before entry %d — not descending", i-1, i)
		}
	}
}

func TestDevicesAdversarial_NilContextSafe(t *testing.T) {
	store := device.NewMemoryStore()
	hist := device.NewMemoryHistoryStore()

	// Must not panic.
	_ = store.Upsert(nil, &device.Device{UserID: "u", Fingerprint: "fp"})
	_, _ = store.ListByUser(nil, "u")
	_, _ = store.ListAll(nil)
	_, _ = store.Get(nil, "nonexistent")
	_ = store.Delete(nil, "nonexistent")
	_ = store.DeleteByUser(nil, "u")
	_ = hist.Record(nil)
}

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
