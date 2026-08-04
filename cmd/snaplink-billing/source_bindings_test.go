package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
)

func TestApplySourceBindingsCreatesUpdatesAndRejectsStaleState(t *testing.T) {
	store := ledger.NewMemorySourceBindingStore()
	created := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	first := sourceBindingFixture(created, 1, true, ledger.Dimension("messages"))
	firstPath := writeSourceBindings(t, []*ledger.SourceBinding{first})
	if err := applySourceBindings(context.Background(), firstPath, store); err != nil {
		t.Fatal(err)
	}
	if err := applySourceBindings(context.Background(), firstPath, store); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}

	second := sourceBindingFixture(created, 2, false, ledger.Dimension("messages"), ledger.Dimension("bytes"))
	second.UpdatedAt = created.Add(time.Minute)
	if err := applySourceBindings(context.Background(), writeSourceBindings(t, []*ledger.SourceBinding{second}), store); err != nil {
		t.Fatalf("versioned update: %v", err)
	}
	stored, err := store.ListSourceBindingsByClient(context.Background(), first.ClientID)
	if err != nil || len(stored) != 1 || !sameSourceBinding(stored[0], second) {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	if err := applySourceBindings(context.Background(), firstPath, store); !errors.Is(err, ledger.ErrSourceBindingConflict) {
		t.Fatalf("stale apply error=%v", err)
	}
}

func TestApplySourceBindingsConcurrentReplicaBootstrapIsIdempotent(t *testing.T) {
	store := ledger.NewMemorySourceBindingStore()
	binding := sourceBindingFixture(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), 1, true,
		ledger.Dimension("messages"))
	path := writeSourceBindings(t, []*ledger.SourceBinding{binding})
	start := make(chan struct{})
	errorsByReplica := make(chan error, 8)
	var replicas sync.WaitGroup
	for range 8 {
		replicas.Add(1)
		go func() {
			defer replicas.Done()
			<-start
			errorsByReplica <- applySourceBindings(context.Background(), path, store)
		}()
	}
	close(start)
	replicas.Wait()
	close(errorsByReplica)
	for err := range errorsByReplica {
		if err != nil {
			t.Fatalf("concurrent bootstrap: %v", err)
		}
	}
}

func TestLoadSourceBindingsRejectsUnknownAndMultipleEnabledClient(t *testing.T) {
	unknown := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(unknown, []byte(`[{"unknown":true}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSourceBindings(unknown); err == nil {
		t.Fatal("unknown field accepted")
	}
	created := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	first := sourceBindingFixture(created, 1, true, ledger.Dimension("messages"))
	second := sourceBindingFixture(created, 1, true, ledger.Dimension("messages"))
	second.ID = "binding-b"
	if _, err := loadSourceBindings(writeSourceBindings(t, []*ledger.SourceBinding{first, second})); err == nil {
		t.Fatal("multiple enabled bindings for one client accepted")
	}
}

func sourceBindingFixture(
	created time.Time, revision uint64, enabled bool, dimensions ...ledger.Dimension,
) *ledger.SourceBinding {
	return &ledger.SourceBinding{
		ID: "binding-a", ClientID: "aero-im-metering", TenantID: "tenant-a",
		SourceSystem: "aero-im", AllowedDimensions: dimensions, Enabled: enabled,
		Revision: revision, CreatedAt: created, UpdatedAt: created,
	}
}

func writeSourceBindings(t *testing.T, bindings []*ledger.SourceBinding) string {
	t.Helper()
	body, err := json.Marshal(bindings)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source-bindings.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
