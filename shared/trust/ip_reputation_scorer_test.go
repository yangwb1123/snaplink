package trust_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/trust"
)

func TestIPReputationScorer_NoSignalWhenUnwired(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	cases := []struct {
		name    string
		scorer  *trust.IPReputationScorer
		signals trust.TrustSignals
	}{
		{"nil_lookup", &trust.IPReputationScorer{}, trust.TrustSignals{RemoteIP: "203.0.113.9", Time: now}},
		{"empty_ip", &trust.IPReputationScorer{Lookup: trust.NewMemoryIPFailureLookup()}, trust.TrustSignals{Time: now}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, err := tc.scorer.Score(ctx, tc.signals)
			if err != nil {
				t.Fatalf("Score returned error: %v", err)
			}
			if len(score.Reasons) != 1 || score.Reasons[0] != "ip_reputation:no_signal" {
				t.Fatalf("Reasons = %v, want [ip_reputation:no_signal]", score.Reasons)
			}
		})
	}
}

func TestIPReputationScorer_CleanBelowThreshold(t *testing.T) {
	lookup := trust.NewMemoryIPFailureLookup()
	now := time.Now()
	// One failure — under the default threshold of 10.
	lookup.Record("203.0.113.9", "alice", now.Add(-time.Minute))

	scorer := &trust.IPReputationScorer{Lookup: lookup}
	score, err := scorer.Score(context.Background(), trust.TrustSignals{RemoteIP: "203.0.113.9", Time: now})
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}
	if score.Reasons[0] != "ip_reputation:clean" {
		t.Fatalf("Reasons = %v, want clean", score.Reasons)
	}
}

func TestIPReputationScorer_SuspiciousAtFailureThreshold(t *testing.T) {
	lookup := trust.NewMemoryIPFailureLookup()
	now := time.Now()
	scorer := &trust.IPReputationScorer{Lookup: lookup, FailureThreshold: 3, DistinctSubjectThreshold: 100}
	for i := 0; i < 3; i++ {
		lookup.Record("203.0.113.9", "alice", now.Add(-time.Minute))
	}

	score, err := scorer.Score(context.Background(), trust.TrustSignals{RemoteIP: "203.0.113.9", Time: now})
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}
	if score.Reasons[0] != "ip_reputation:high_failure_volume" {
		t.Fatalf("Reasons = %v, want high_failure_volume at exact threshold", score.Reasons)
	}
}

func TestIPReputationScorer_SuspiciousOnDistinctSubjectSpray(t *testing.T) {
	lookup := trust.NewMemoryIPFailureLookup()
	now := time.Now()
	scorer := &trust.IPReputationScorer{Lookup: lookup, FailureThreshold: 1000, DistinctSubjectThreshold: 2}
	lookup.Record("203.0.113.9", "alice", now.Add(-time.Minute))
	lookup.Record("203.0.113.9", "bob", now.Add(-time.Minute))

	score, err := scorer.Score(context.Background(), trust.TrustSignals{RemoteIP: "203.0.113.9", Time: now})
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}
	if score.Reasons[0] != "ip_reputation:high_failure_volume" {
		t.Fatalf("Reasons = %v, want spray to trip distinct-subject threshold", score.Reasons)
	}
}

func TestIPReputationScorer_WindowExcludesOldFailures(t *testing.T) {
	lookup := trust.NewMemoryIPFailureLookup()
	now := time.Now()
	scorer := &trust.IPReputationScorer{Lookup: lookup, Window: time.Minute, FailureThreshold: 1}
	lookup.Record("203.0.113.9", "alice", now.Add(-time.Hour)) // outside the 1-minute window

	score, err := scorer.Score(context.Background(), trust.TrustSignals{RemoteIP: "203.0.113.9", Time: now})
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}
	if score.Reasons[0] != "ip_reputation:clean" {
		t.Fatalf("Reasons = %v, want clean (old failure outside window)", score.Reasons)
	}
}

type erroringIPFailureLookup struct{ err error }

func (e erroringIPFailureLookup) CountFailures(context.Context, string, time.Time) (int, int, error) {
	return 0, 0, e.err
}

func TestIPReputationScorer_PropagatesLookupError(t *testing.T) {
	wantErr := errors.New("store unreachable")
	scorer := &trust.IPReputationScorer{Lookup: erroringIPFailureLookup{err: wantErr}}
	_, err := scorer.Score(context.Background(), trust.TrustSignals{RemoteIP: "203.0.113.9", Time: time.Now()})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestIPReputationScorer_Name(t *testing.T) {
	if got := (&trust.IPReputationScorer{}).Name(); got != "ip_reputation" {
		t.Fatalf("Name() = %q, want ip_reputation", got)
	}
}
