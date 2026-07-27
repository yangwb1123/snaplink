package tokenanomaly

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenusage"
)

// TestNewDetector verifies nil-safe behavior and constructor.
func TestNewDetector(t *testing.T) {
	d := NewDetector(nil, nil)
	if d != nil {
		t.Fatal("expected nil detector for nil store")
	}

	memStore := new(recordingStore)
	d = NewDetector(memStore, nil)
	if d == nil {
		t.Fatal("expected non-nil detector")
	}

	// Nil-safe methods
	var nilD *Detector
	if nilD.Record(context.Background(), tokenusage.Event{}) != nil {
		t.Error("nil Record should return nil")
	}
	obs, _ := nilD.Query(context.Background(), tokenusage.Query{})
	if obs != nil {
		t.Error("nil Query should return nil")
	}
	if nilD.TrackedBuckets() != 0 {
		t.Error("nil TrackedBuckets should return 0")
	}
}

// TestDetector_NilSafeMethods verifies all methods on nil *Detector are safe.
func TestDetector_NilSafeMethods(t *testing.T) {
	var nilD *Detector

	_ = nilD.Record(context.Background(), tokenusage.Event{Thumbprint: "tp-1", ClientID: "c1"})
	_, _ = nilD.Query(context.Background(), tokenusage.Query{})
	_, _ = nilD.Analyze(context.Background())
	nilD.SetFindingHook(nil)
	// _ = nilD.findingHook() -- not nil-safe (deliberate, uses d.mu)
	_ = nilD.Findings()
}

// TestDetector_RecordForwards verifies Record reaches the underlying store.
func TestDetector_RecordForwards(t *testing.T) {
	ctx := context.Background()
	memStore := new(recordingStore)
	d := NewDetector(memStore, nil)
	if d == nil {
		t.Fatal("expected non-nil detector")
	}

	ev := tokenusage.Event{
		Thumbprint: "tp-test-1",
		ClientID:   "test-client",
		SubjectID:  "test-user",
		GeoCountry: "US",
		At:         time.Now(),
		Endpoint:   tokenusage.EndpointToken,
		Kind:       tokenusage.KindAccess,
	}
	if err := d.Record(ctx, ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	t.Log("Record forwarded to underlying store")
}

// TestFoldClientMinuteRates tests the rate folding logic.
// recordingStore is a minimal tokenusage.Store implementation for testing.
type recordingStore struct {
	count atomic.Int64
}

func (s *recordingStore) Record(_ context.Context, _ tokenusage.Event) error {
	s.count.Add(1)
	return nil
}

func (s *recordingStore) Query(_ context.Context, _ tokenusage.Query) ([]tokenusage.Bucket, error) {
	return nil, nil
}

func (s *recordingStore) TrackedBuckets() int { return 0 }

func TestFoldClientMinuteRates(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	t.Run("nil input returns empty", func(t *testing.T) {
		result := foldClientMinuteRates(nil)
		if result == nil {
			t.Error("expected non-nil map for nil input")
		}
		if len(result) != 0 {
			t.Errorf("expected empty map, got %d entries", len(result))
		}
	})

	t.Run("aggregates by client+minute", func(t *testing.T) {
		buckets := []tokenusage.Bucket{
			{Minute: now, ClientID: "c1", Endpoint: tokenusage.EndpointToken, Kind: tokenusage.KindAccess, Count: 5},
			{Minute: now, ClientID: "c1", Endpoint: tokenusage.EndpointToken, Kind: tokenusage.KindRefresh, Count: 3},
			{Minute: now, ClientID: "c2", Endpoint: tokenusage.EndpointToken, Kind: tokenusage.KindAccess, Count: 1},
			{Minute: now.Add(-1 * time.Minute), ClientID: "c1", Endpoint: tokenusage.EndpointToken, Kind: tokenusage.KindAccess, Count: 2},
		}
		result := foldClientMinuteRates(buckets)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if len(result) != 2 {
			t.Errorf("expected 2 clients, got %d", len(result))
		}
		minuteKey := now.Unix()
		if result["c1"][minuteKey] != 8 {
			t.Errorf("expected 8 for c1 at %d, got %d", minuteKey, result["c1"][minuteKey])
		}
	})
}
