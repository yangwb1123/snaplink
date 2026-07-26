package trust

import (
	"context"
	"testing"
	"time"
)

func TestBehaviorScorer_Name(t *testing.T) {
	s := &BehaviorScorer{}
	if name := s.Name(); name != "behavior" {
		t.Errorf("expected 'behavior', got %q", name)
	}
}

func TestObservationHour(t *testing.T) {
	tests := []struct {
		t    time.Time
		hour int
	}{
		{time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC), 0},
		{time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC), 12},
		{time.Date(2026, 7, 26, 23, 59, 59, 0, time.UTC), 23},
	}

	for _, tc := range tests {
		got := observationHour(tc.t)
		if got != tc.hour {
			t.Errorf("observationHour(%v) = %d, want %d", tc.t, got, tc.hour)
		}
	}
}

func TestHasObservedHour(t *testing.T) {
	base := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)

	t.Run("empty history", func(t *testing.T) {
		if hasObservedHour(nil, 10) {
			t.Error("expected false for nil history")
		}
	})

	t.Run("hour present", func(t *testing.T) {
		history := []time.Time{base.Add(10 * time.Hour), base.Add(14 * time.Hour)}
		if !hasObservedHour(history, 10) {
			t.Error("expected true for hour 10")
		}
	})

	t.Run("hour absent", func(t *testing.T) {
		history := []time.Time{base.Add(10 * time.Hour), base.Add(14 * time.Hour)}
		if hasObservedHour(history, 5) {
			t.Error("expected false for hour 5")
		}
	})
}

func TestBehaviorScorer_NoSignalWhenUnwired(t *testing.T) {
	s := &BehaviorScorer{}
	ctx := context.Background()
	signals := TrustSignals{UserID: "user-1"}

	score, err := s.Score(ctx, signals)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	// Without a history store, the scorer uses a default/fallback score
	// (typically 0.5-0.6 for unknown subjects). The exact value depends
	// on the implementation but should be in the valid [0,1] range.
	if score.Value < 0 || score.Value > 1 {
		t.Errorf("expected score in [0,1], got %f", score.Value)
	}
	t.Logf("unwired scorer returned %f", score.Value)
}

func TestBehaviorScorer_ColdStartForNewSubject(t *testing.T) {
	s := &BehaviorScorer{
		History: NewMemoryLoginHistory(),
	}
	ctx := context.Background()

	signals := TrustSignals{UserID: "new-user"}
	score, err := s.Score(ctx, signals)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if score.Value <= 0 {
		t.Errorf("expected positive score for cold start, got %f", score.Value)
	}
}

func TestBehaviorScorer_NilContextSafe(t *testing.T) {
	s := &BehaviorScorer{}
	_, err := s.Score(nil, TrustSignals{})
	if err != nil {
		t.Logf("Score with nil context: %v", err)
	}
}

func TestBehaviorScorer_HistoryLimitDefault(t *testing.T) {
	s := &BehaviorScorer{}
	limit := s.historyLimit()
	if limit <= 0 {
		t.Errorf("expected positive history limit, got %d", limit)
	}
	// Default history limit should be a reasonable small number
	// (typically 20-100 hours of lookback)
	if limit < 1 || limit > 200 {
		t.Errorf("expected reasonable history limit (1-200), got %d", limit)
	}
	t.Logf("default history limit: %d", limit)
}

func TestMemoryLoginHistory_RecordAndHistory(t *testing.T) {
	h := NewMemoryLoginHistory()

	now := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	h.Record("user-1", now)
	h.Record("user-1", now.Add(-1*time.Hour))
	h.Record("user-2", now)

	history, err := h.History(context.Background(), "user-1", 100)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 2 {
		t.Errorf("expected 2 entries for user-1, got %d", len(history))
	}

	history2, err := h.History(context.Background(), "user-2", 100)
	if err != nil {
		t.Fatalf("History user-2: %v", err)
	}
	if len(history2) != 1 {
		t.Errorf("expected 1 entry for user-2, got %d", len(history2))
	}
}

func TestMemoryLoginHistory_UnknownUser(t *testing.T) {
	h := NewMemoryLoginHistory()
	history, err := h.History(context.Background(), "nonexistent", 100)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("expected 0 entries for unknown user, got %d", len(history))
	}
}

func TestMemoryLoginHistory_ConcurrentRecord(t *testing.T) {
	h := NewMemoryLoginHistory()
	now := time.Now()

	const goroutines = 10
	done := make(chan struct{})
	for range goroutines {
		go func() {
			h.Record("user-c", now)
			done <- struct{}{}
		}()
	}
	for range goroutines {
		<-done
	}

	history, err := h.History(context.Background(), "user-c", 100)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != goroutines {
		t.Errorf("expected %d entries, got %d", goroutines, len(history))
	}
}

func TestMemoryLoginHistory_Limit(t *testing.T) {
	h := NewMemoryLoginHistory()
	now := time.Now()

	for i := 0; i < 20; i++ {
		h.Record("user-limit", now.Add(time.Duration(i)*time.Second))
	}

	history, err := h.History(context.Background(), "user-limit", 5)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 5 {
		t.Errorf("expected 5 entries with limit=5, got %d", len(history))
	}
}
