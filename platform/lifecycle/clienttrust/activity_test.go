package clienttrust_test

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/lifecycle/clienttrust"
)

func TestMemoryClientActivityStore_RecordRequiresClientID(t *testing.T) {
	t.Parallel()
	store := clienttrust.NewMemoryClientActivityStore()
	err := store.Record(context.Background(), clienttrust.ClientActivityEvent{Kind: clienttrust.ClientActivityAuthFailure})
	if err != clienttrust.ErrClientIDRequired {
		t.Fatalf("Record with empty ClientID: got %v, want ErrClientIDRequired", err)
	}
}

func TestMemoryClientActivityStore_SummarizeColdStart(t *testing.T) {
	t.Parallel()
	store := clienttrust.NewMemoryClientActivityStore()
	sum, err := store.Summarize(context.Background(), "unknown-client", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if sum.HasHistory {
		t.Error("a client with zero recorded events must report HasHistory=false")
	}
}

func TestMemoryClientActivityStore_SummarizeCountsAndWindow(t *testing.T) {
	t.Parallel()
	store := clienttrust.NewMemoryClientActivityStore()
	ctx := context.Background()
	now := time.Now()

	// Outside the window — must not be counted.
	mustRecord(t, store, "c1", clienttrust.ClientActivityAuthFailure, now.Add(-48*time.Hour))
	// Inside the window.
	mustRecord(t, store, "c1", clienttrust.ClientActivityAuthFailure, now.Add(-time.Minute))
	mustRecord(t, store, "c1", clienttrust.ClientActivityAuthSuccess, now.Add(-time.Minute))
	mustRecord(t, store, "c1", clienttrust.ClientActivitySecretRotation, now.Add(-time.Minute))
	mustRecord(t, store, "c1", clienttrust.ClientActivityScopeAnomaly, now.Add(-time.Minute))

	sum, err := store.Summarize(ctx, "c1", now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if !sum.HasHistory {
		t.Error("expected HasHistory=true")
	}
	if sum.AuthFailure != 1 {
		t.Errorf("AuthFailure = %d, want 1 (the 48h-old failure is outside the window)", sum.AuthFailure)
	}
	if sum.AuthSuccess != 1 {
		t.Errorf("AuthSuccess = %d, want 1", sum.AuthSuccess)
	}
	if sum.SecretRotations != 1 {
		t.Errorf("SecretRotations = %d, want 1", sum.SecretRotations)
	}
	if sum.ScopeAnomalies != 1 {
		t.Errorf("ScopeAnomalies = %d, want 1", sum.ScopeAnomalies)
	}
	if sum.LastNegativeAt.IsZero() {
		t.Error("LastNegativeAt must be set when a negative event fell in the window")
	}
}

func mustRecord(t *testing.T, store *clienttrust.MemoryClientActivityStore, clientID string, kind clienttrust.ClientActivityKind, at time.Time) {
	t.Helper()
	if err := store.Record(context.Background(), clienttrust.ClientActivityEvent{
		ClientID: clientID, Kind: kind, Timestamp: at,
	}); err != nil {
		t.Fatalf("Record(%s): %v", kind, err)
	}
}
