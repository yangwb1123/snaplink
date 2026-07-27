package bootstrap_test

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	ssobootstrap "github.com/yangwb1123/snaplink/interfaces/ssoclient/bootstrap"
)

func TestNew_RejectsReservedNamespace(t *testing.T) {
	t.Parallel()
	if _, err := ssobootstrap.New("sso-server", filepath.Join(t.TempDir(), "s.json")); err == nil {
		t.Fatal("expected error for reserved namespace")
	}
}

func TestNew_RequiresArgs(t *testing.T) {
	t.Parallel()
	if _, err := ssobootstrap.New("", "x"); err == nil {
		t.Fatal("expected error for empty namespace")
	}
	if _, err := ssobootstrap.New("ns", ""); err == nil {
		t.Fatal("expected error for empty state path")
	}
}

func TestRun_AppliesStepsAndSkipsRepeats(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	bs, err := ssobootstrap.New("billing", path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = bs.Close() }()

	var hits atomic.Int64
	bs.Register(ssobootstrap.StepFunc("create_schema", 1, func(_ context.Context) error {
		hits.Add(1)
		return nil
	}))
	if err := bs.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := bs.Run(context.Background()); err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("expected step to run once across two Run calls, got %d", got)
	}
}
