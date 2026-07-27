package device

import (
	"sync"
	"testing"
	"time"
)

func TestMemoryHistoryStore_Adversarial_ConcurrentRecord(t *testing.T) {
	s := NewMemoryHistoryStore()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for n := range goroutines {
		go func(val int) {
			defer wg.Done()
			rec := &LoginRecord{
				UserID:     "user-h",
				Time:       time.Now(),
				IP:         "10.0.0.1",
				Provider:   "password",
				Success:    true,
				DeviceID:   "dev-" + itoa(val),
				TrustScore: float64(val) / float64(goroutines),
			}
			_ = s.Record(rec)
		}(n)
	}
	wg.Wait()

	history, err := s.RecentByUser("user-h", 100)
	if err != nil {
		t.Fatalf("RecentByUser: %v", err)
	}
	if len(history) != goroutines {
		t.Errorf("expected %d history entries, got %d", goroutines, len(history))
	}
}

func TestMemoryHistoryStore_Adversarial_NilRecord(t *testing.T) {
	s := NewMemoryHistoryStore()
	err := s.Record(nil)
	if err == nil {
		t.Error("expected error for nil record")
	}
}

func TestMemoryHistoryStore_Adversarial_EmptyList(t *testing.T) {
	s := NewMemoryHistoryStore()

	entries, err := s.RecentByUser("nonexistent", 10)
	if err != nil {
		t.Fatalf("RecentByUser: %v", err)
	}
	if entries == nil || len(entries) != 0 {
		t.Errorf("expected empty list for nonexistent user, got %v", entries)
	}
}

func TestMemoryHistoryStore_Adversarial_OrderPreserved(t *testing.T) {
	s := NewMemoryHistoryStore()

	base := time.Now()
	for idx := range 5 {
		rec := &LoginRecord{
			UserID:   "user-order",
			Time:     base.Add(time.Duration(idx) * time.Second),
			Provider: "password",
			Success:  true,
		}
		_ = s.Record(rec)
	}

	entries, _ := s.RecentByUser("user-order", 10)
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Time.Before(entries[i].Time) {
			t.Errorf("entry %d (time=%v) is before entry %d (time=%v) — expected descending",
				i-1, entries[i-1].Time, i, entries[i].Time)
		}
	}
}

func TestMemoryHistoryStore_Adversarial_MultipleUsers(t *testing.T) {
	s := NewMemoryHistoryStore()

	for range 10 {
		_ = s.Record(&LoginRecord{UserID: "user-a", Success: true})
		_ = s.Record(&LoginRecord{UserID: "user-b", Success: true})
	}

	aEntries, _ := s.RecentByUser("user-a", 100)
	bEntries, _ := s.RecentByUser("user-b", 100)
	if len(aEntries) != 10 || len(bEntries) != 10 {
		t.Errorf("expected 10 each, got a=%d b=%d", len(aEntries), len(bEntries))
	}
}

func TestMemoryHistoryStore_Adversarial_DeviceScopedQuery(t *testing.T) {
	s := NewMemoryHistoryStore()

	for range 5 {
		_ = s.Record(&LoginRecord{UserID: "user-d", DeviceID: "dev-alice", Success: true})
		_ = s.Record(&LoginRecord{UserID: "user-d", DeviceID: "dev-bob", Success: true})
	}

	aliceDev, _ := s.RecentByDevice("dev-alice", 10)
	if len(aliceDev) != 5 {
		t.Errorf("expected 5 records for dev-alice, got %d", len(aliceDev))
	}
	for _, r := range aliceDev {
		if r.DeviceID != "dev-alice" {
			t.Errorf("expected DeviceID=dev-alice, got %s", r.DeviceID)
		}
	}
}

func TestMemoryHistoryStore_Adversarial_Limit(t *testing.T) {
	s := NewMemoryHistoryStore()

	for range 20 {
		_ = s.Record(&LoginRecord{UserID: "u", Success: true})
	}

	entries, _ := s.RecentByUser("u", 5)
	if len(entries) != 5 {
		t.Errorf("expected 5 entries with limit=5, got %d", len(entries))
	}
}
