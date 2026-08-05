package trust_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/trust"
)

func TestBehaviorScorer_NoSignalWhenUnwired(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	cases := []struct {
		name    string
		scorer  *trust.BehaviorScorer
		signals trust.TrustSignals
	}{
		{"nil_history", &trust.BehaviorScorer{}, trust.TrustSignals{UserID: "alice", Time: now}},
		{"empty_user_id", &trust.BehaviorScorer{History: trust.NewMemoryLoginHistory()}, trust.TrustSignals{Time: now}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, err := tc.scorer.Score(ctx, tc.signals)
			if err != nil {
				t.Fatalf("Score returned error: %v", err)
			}
			if score.Reasons[0] != "behavior:no_signal" {
				t.Fatalf("Reasons = %v, want behavior:no_signal", score.Reasons)
			}
		})
	}
}

func TestBehaviorScorer_ColdStartForNewSubject(t *testing.T) {
	history := trust.NewMemoryLoginHistory()
	scorer := &trust.BehaviorScorer{History: history}

	score, err := scorer.Score(context.Background(), trust.TrustSignals{UserID: "brand-new", Time: time.Now()})
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}
	if score.Reasons[0] != "behavior:cold_start" {
		t.Fatalf("Reasons = %v, want behavior:cold_start", score.Reasons)
	}
}

func TestBehaviorScorer_TypicalVsAtypicalHour(t *testing.T) {
	history := trust.NewMemoryLoginHistory()
	// Anchor "typical" logins at 09:00 UTC.
	anchor := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	history.Record("alice", anchor)

	scorer := &trust.BehaviorScorer{History: history}

	t.Run("typical_hour", func(t *testing.T) {
		now := time.Date(2026, 1, 5, 9, 30, 0, 0, time.UTC)
		score, err := scorer.Score(context.Background(), trust.TrustSignals{UserID: "alice", Time: now})
		if err != nil {
			t.Fatalf("Score returned error: %v", err)
		}
		if score.Reasons[0] != "behavior:typical_hour" {
			t.Fatalf("Reasons = %v, want behavior:typical_hour", score.Reasons)
		}
	})

	t.Run("atypical_hour", func(t *testing.T) {
		now := time.Date(2026, 1, 5, 3, 30, 0, 0, time.UTC)
		score, err := scorer.Score(context.Background(), trust.TrustSignals{UserID: "alice", Time: now})
		if err != nil {
			t.Fatalf("Score returned error: %v", err)
		}
		if score.Reasons[0] != "behavior:atypical_hour" {
			t.Fatalf("Reasons = %v, want behavior:atypical_hour", score.Reasons)
		}
	})
}

type erroringLoginHistory struct{ err error }

func (e erroringLoginHistory) History(context.Context, string, string, int) ([]time.Time, error) {
	return nil, e.err
}

func TestBehaviorScorer_PropagatesHistoryError(t *testing.T) {
	wantErr := errors.New("store unreachable")
	scorer := &trust.BehaviorScorer{History: erroringLoginHistory{err: wantErr}}
	_, err := scorer.Score(context.Background(), trust.TrustSignals{UserID: "alice", Time: time.Now()})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestBehaviorScorer_Name(t *testing.T) {
	if got := (&trust.BehaviorScorer{}).Name(); got != "behavior" {
		t.Fatalf("Name() = %q, want behavior", got)
	}
}

func TestMemoryLoginHistory_LimitCapsResults(t *testing.T) {
	history := trust.NewMemoryLoginHistory()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		history.Record("alice", base.Add(time.Duration(i)*time.Hour))
	}
	got, err := history.History(context.Background(), "", "alice", 2)
	if err != nil {
		t.Fatalf("History returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
}
