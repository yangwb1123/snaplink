package admingovernance

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryApprovalStore_ProposeApproveLifecycle(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()

	c, err := store.Propose(ctx, ChangeRequest{
		ID: "chg1", ActionType: "tenant_delete", Payload: []byte(`{"id":"acme"}`),
		Reason: "customer offboarding", ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if c.Status != ChangeStatusPending {
		t.Fatalf("Status = %q; want pending", c.Status)
	}

	got, err := store.Get(ctx, "chg1")
	if err != nil || got.ID != "chg1" {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	list, err := store.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}

	approved, err := store.Approve(ctx, "chg1", "admin-b")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if approved.Status != ChangeStatusApproved || approved.ApprovedBy != "admin-b" {
		t.Fatalf("approved = %+v", approved)
	}
}

func TestMemoryApprovalStore_SelfApprovalRejected(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "x", ProposedBy: "admin-a"})

	_, err := store.Approve(ctx, "chg1", "admin-a")
	if !errors.Is(err, ErrChangeSelfApproval) {
		t.Fatalf("Approve self = %v; want ErrChangeSelfApproval", err)
	}
	_, err = store.Approve(ctx, "chg1", "")
	if !errors.Is(err, ErrChangeSelfApproval) {
		t.Fatalf("Approve empty approver = %v; want ErrChangeSelfApproval", err)
	}
}

func TestMemoryApprovalStore_NotPendingAfterDecision(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "x", ProposedBy: "admin-a"})
	if _, err := store.Approve(ctx, "chg1", "admin-b"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if _, err := store.Approve(ctx, "chg1", "admin-c"); !errors.Is(err, ErrChangeNotPending) {
		t.Fatalf("second approve = %v; want ErrChangeNotPending", err)
	}
	if _, err := store.Reject(ctx, "chg1", "admin-c"); !errors.Is(err, ErrChangeNotPending) {
		t.Fatalf("reject already-approved = %v; want ErrChangeNotPending", err)
	}
}

func TestMemoryApprovalStore_Reject(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "x", ProposedBy: "admin-a"})
	rejected, err := store.Reject(ctx, "chg1", "admin-b")
	if err != nil || rejected.Status != ChangeStatusRejected {
		t.Fatalf("Reject = %+v, %v", rejected, err)
	}
}

func TestMemoryApprovalStore_UnknownID(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	if _, err := store.Get(ctx, "nope"); !errors.Is(err, ErrChangeNotFound) {
		t.Fatalf("Get unknown = %v; want ErrChangeNotFound", err)
	}
	if _, err := store.Approve(ctx, "nope", "admin-b"); !errors.Is(err, ErrChangeNotFound) {
		t.Fatalf("Approve unknown = %v; want ErrChangeNotFound", err)
	}
}

func TestApproveAndApply_InvokesRegisteredApplier(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{
		ID: "chg1", ActionType: "tenant_delete", Payload: []byte(`{"id":"acme"}`), ProposedBy: "admin-a",
	})

	var appliedPayload []byte
	reg := NewRegistry()
	reg.Register("tenant_delete", func(_ context.Context, payload []byte) error {
		appliedPayload = payload
		return nil
	})

	c, err := ApproveAndApply(ctx, store, reg, "chg1", "admin-b")
	if err != nil {
		t.Fatalf("ApproveAndApply: %v", err)
	}
	if c.Status != ChangeStatusApplied {
		t.Fatalf("Status = %q; want applied", c.Status)
	}
	if string(appliedPayload) != `{"id":"acme"}` {
		t.Fatalf("applier payload = %q", appliedPayload)
	}
}

func TestApproveAndApply_NoRegisteredApplierStaysApproved(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "unregistered", ProposedBy: "admin-a"})

	c, err := ApproveAndApply(ctx, store, nil, "chg1", "admin-b")
	if err != nil {
		t.Fatalf("ApproveAndApply: %v", err)
	}
	if c.Status != ChangeStatusApproved {
		t.Fatalf("Status = %q; want approved (no applier registered)", c.Status)
	}
}

func TestApproveAndApply_FailedApplierMarksFailed(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "boom", ProposedBy: "admin-a"})

	reg := NewRegistry()
	reg.Register("boom", func(context.Context, []byte) error { return errors.New("downstream unavailable") })

	c, err := ApproveAndApply(ctx, store, reg, "chg1", "admin-b")
	if err != nil {
		t.Fatalf("ApproveAndApply: %v", err)
	}
	if c.Status != ChangeStatusFailed {
		t.Fatalf("Status = %q; want failed", c.Status)
	}
	if c.FailureNote == "" {
		t.Fatal("FailureNote empty; want the applier error recorded")
	}
}

func TestApproveAndApply_PropagatesApproveError(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "x", ProposedBy: "admin-a"})

	if _, err := ApproveAndApply(ctx, store, nil, "chg1", "admin-a"); !errors.Is(err, ErrChangeSelfApproval) {
		t.Fatalf("ApproveAndApply self-approval = %v; want ErrChangeSelfApproval", err)
	}
}

func TestRequiredActionTypes(t *testing.T) {
	empty := NewRequiredActionTypes(nil)
	if !empty.Allows("anything") {
		t.Error("empty set must allow any action type")
	}
	restricted := NewRequiredActionTypes([]string{"tenant_delete", "client_delete"})
	if !restricted.Allows("tenant_delete") {
		t.Error("restricted set must allow a listed type")
	}
	if restricted.Allows("unrelated_action") {
		t.Error("restricted set must reject an unlisted type")
	}
}
