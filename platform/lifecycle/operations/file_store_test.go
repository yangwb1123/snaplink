package operations

import (
	"context"
	"errors"
	"testing"
)

func TestFileStorePersistsFinalStateAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	operation, err := Start(ctx, first, "snapshot_restore", "snap-1")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := BeginStep(ctx, first, &operation, "apply_resources"); err != nil {
		t.Fatalf("begin step: %v", err)
	}
	stepErr := errors.New("injected apply failure")
	if err := FinishStep(ctx, first, &operation, stepErr); err != nil {
		t.Fatalf("finish step: %v", err)
	}
	if err := AddCompensation(
		ctx, first, &operation, "restore_previous", StepSucceeded, "",
	); err != nil {
		t.Fatalf("compensation: %v", err)
	}
	if err := Finish(ctx, first, &operation, nil, stepErr); err != nil {
		t.Fatalf("finish: %v", err)
	}

	reopened, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	got, err := reopened.Get(ctx, operation.ID)
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.State != StateFailed || got.Error != stepErr.Error() ||
		len(got.Steps) != 1 || got.Steps[0].State != StepFailed ||
		len(got.Compensations) != 1 {
		t.Fatalf("persisted operation = %+v", got)
	}
}
