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

func TestMemoryHistoryStore_RecordCopiesInput(t *testing.T) {
	s := NewMemoryHistoryStore()
	record := &LoginRecord{
		ID: "record-1", UserID: "user-1", Time: time.Now(), IP: "192.0.2.1",
		Provider: "password", Success: true, SessionID: "session-1",
	}
	if err := s.Record(record); err != nil {
		t.Fatalf("Record: %v", err)
	}
	record.UserID = "attacker"
	record.IP = "192.0.2.99"
	record.Success = false

	got, err := s.RecentByUser("user-1", 0)
	if err != nil {
		t.Fatalf("RecentByUser: %v", err)
	}
	if len(got) != 1 || got[0].UserID != "user-1" || got[0].IP != "192.0.2.1" || !got[0].Success {
		t.Fatalf("stored record changed through input: %+v", got)
	}
}

func TestMemoryHistoryStore_QueriesReturnCopies(t *testing.T) {
	s := NewMemoryHistoryStore()
	_ = s.Record(&LoginRecord{
		ID: "record-1", UserID: "user-1", DeviceID: "device-1", Time: time.Now(),
		Provider: "password", Success: true, SessionID: "session-1", TrustScore: 0.8,
	})

	byUser, err := s.RecentByUser("user-1", 0)
	if err != nil || len(byUser) != 1 {
		t.Fatalf("RecentByUser: records=%v err=%v", byUser, err)
	}
	byUser[0].Provider = "tampered"
	byUser[0].Success = false

	byDevice, err := s.RecentByDevice("device-1", 0)
	if err != nil || len(byDevice) != 1 {
		t.Fatalf("RecentByDevice: records=%v err=%v", byDevice, err)
	}
	if byDevice[0].Provider != "password" || !byDevice[0].Success {
		t.Fatalf("user query mutated stored record: %+v", byDevice[0])
	}
	byDevice[0].SessionID = "tampered"
	byDevice[0].TrustScore = 0

	again, err := s.RecentByUser("user-1", 0)
	if err != nil || len(again) != 1 {
		t.Fatalf("second RecentByUser: records=%v err=%v", again, err)
	}
	if again[0].SessionID != "session-1" || again[0].TrustScore != 0.8 {
		t.Fatalf("device query mutated stored record: %+v", again[0])
	}
}
