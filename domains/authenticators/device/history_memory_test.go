package device

import (
	"testing"
	"time"
)

func TestMemoryHistoryStore_RecordAndRecentByUser(t *testing.T) {
	s := NewMemoryHistoryStore()
	now := time.Now()

	_ = s.Record(&LoginRecord{UserID: "u1", Time: now.Add(-1 * time.Hour)})
	_ = s.Record(&LoginRecord{UserID: "u1", Time: now})
	_ = s.Record(&LoginRecord{UserID: "u2", Time: now})

	recs, err := s.RecentByUser("u1", 0)
	if err != nil {
		t.Fatalf("RecentByUser: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("expected 2 records for u1, got %d", len(recs))
	}
	// Most recent first.
	if !recs[0].Time.After(recs[1].Time) {
		t.Error("records should be ordered by time descending")
	}
}

func TestMemoryHistoryStore_RecentByUser_Limit(t *testing.T) {
	s := NewMemoryHistoryStore()
	for i := 0; i < 10; i++ {
		_ = s.Record(&LoginRecord{UserID: "u1"})
	}
	recs, _ := s.RecentByUser("u1", 3)
	if len(recs) != 3 {
		t.Errorf("expected 3 records (limit=3), got %d", len(recs))
	}
}

func TestMemoryHistoryStore_RecentByDevice(t *testing.T) {
	s := NewMemoryHistoryStore()
	_ = s.Record(&LoginRecord{UserID: "u1", DeviceID: "dev1"})
	_ = s.Record(&LoginRecord{UserID: "u1", DeviceID: "dev1"})
	_ = s.Record(&LoginRecord{UserID: "u2", DeviceID: "dev2"})

	recs, err := s.RecentByDevice("dev1", 0)
	if err != nil {
		t.Fatalf("RecentByDevice: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("expected 2 records for dev1, got %d", len(recs))
	}
}

func TestMemoryHistoryStore_Empty(t *testing.T) {
	s := NewMemoryHistoryStore()
	recs, _ := s.RecentByUser("nobody", 0)
	if len(recs) != 0 {
		t.Errorf("expected empty, got %d", len(recs))
	}
}

func TestMemoryHistoryStore_AutoGenerateID(t *testing.T) {
	s := NewMemoryHistoryStore()
	r := &LoginRecord{UserID: "u1"}
	_ = s.Record(r)
	if r.ID == "" {
		t.Error("ID should be auto-generated")
	}
}

func TestMemoryHistoryStore_RecentByUser_Ordering(t *testing.T) {
	s := NewMemoryHistoryStore()
	// Add records in non-chronological order.
	_ = s.Record(&LoginRecord{UserID: "u1", Time: time.Now().Add(-2 * time.Hour)})
	_ = s.Record(&LoginRecord{UserID: "u1", Time: time.Now().Add(-1 * time.Hour)})
	_ = s.Record(&LoginRecord{UserID: "u1", Time: time.Now()})

	recs, _ := s.RecentByUser("u1", 0)
	if len(recs) != 3 {
		t.Fatalf("expected 3, got %d", len(recs))
	}
	// Should be newest first.
	for i := 1; i < len(recs); i++ {
		if recs[i-1].Time.Before(recs[i].Time) {
			t.Errorf("record %d (time=%v) should be after record %d (time=%v)",
				i-1, recs[i-1].Time, i, recs[i].Time)
		}
	}
}
